// src/main.rs
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use askama::Template;
use serde::Deserialize;
use sqlx::{PgPool, Row};
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};

mod auth;
mod db;

#[derive(Clone)]
struct AppState {
    db: PgPool,
}

#[derive(Clone)]
struct CurrentUser {
    id: i64,
    username: String,
    role: String,
}

/* ---------------- Templates ---------------- */

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    logged_in: bool,
    username: String,
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate;

#[derive(Template)]
#[template(path = "poems_list.html")]
struct PoemsListTemplate {
    logged_in: bool,
    username: String,
    poems: Vec<PoemListItem>,
}

#[derive(Template)]
#[template(path = "poem_view.html")]
struct PoemViewTemplate {
    logged_in: bool,
    username: String,
    poem: PoemView,
    can_edit: bool,
    comments: Vec<CommentView>,
}

#[derive(Template)]
#[template(path = "poem_new.html")]
struct PoemNewTemplate {
    logged_in: bool,
    username: String,
}

#[derive(Template)]
#[template(path = "poem_edit.html")]
struct PoemEditTemplate {
    logged_in: bool,
    username: String,
    poem: PoemView,
}

#[derive(Template)]
#[template(path = "my_drafts.html")]
struct MyDraftsTemplate {
    logged_in: bool,
    username: String,
    poems: Vec<MyPoemItem>,
}

/* ---------------- Main ---------------- */

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let pool = db::connect().await?;
    let state = AppState { db: pool };

    let app = Router::new()
        // auth
        .route("/", get(index))
        .route("/register", get(register_page).post(register_post))
        .route("/login", get(login_page).post(login_post))
        .route("/logout", post(logout_post))
        // poems
        .route("/poems", get(poems_list).post(poem_create))
        .route("/poems/new", get(poem_new_page))
        .route("/poems/:id", get(poem_view).post(poem_update))
        .route("/poems/:id/edit", get(poem_edit_page))
        .route("/poems/:id/publish", post(poem_publish))
        .route("/poems/:id/delete", post(poem_delete))
        .route("/poems/:id/comments", post(comment_add))
        .route("/me/drafts", get(my_drafts))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/* ---------------- Helpers ---------------- */

fn render_ok<T: Template>(t: T) -> axum::response::Response {
    match t.render() {
        Ok(s) => Html(s).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response(),
    }
}

fn session_user_id(cookies: &Cookies) -> Option<i64> {
    let c = cookies.get("session")?;
    c.value().parse::<i64>().ok().filter(|id| *id > 0)
}

async fn current_user(db: &PgPool, cookies: &Cookies) -> Option<CurrentUser> {
    let id = session_user_id(cookies)?;
    let row = sqlx::query("select id, username, role from users where id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()??;

    Some(CurrentUser {
        id: row.get("id"),
        username: row.get("username"),
        role: row.get("role"),
    })
}

fn is_admin_or_mod(u: &CurrentUser) -> bool {
    u.role == "admin" || u.role == "mod"
}

fn set_session(cookies: &Cookies, user_id: i64) {
    let mut c = Cookie::new("session", user_id.to_string());
    c.set_http_only(true);
    c.set_secure(true);
    c.set_path("/");
    cookies.add(c);
}

fn time_ago(t: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let delta = now - t;

    if delta.num_seconds() < 60 {
        "just now".to_string()
    } else if delta.num_minutes() < 60 {
        format!("{} minutes ago", delta.num_minutes())
    } else if delta.num_hours() < 24 {
        format!("{} hours ago", delta.num_hours())
    } else if delta.num_days() < 7 {
        format!("{} days ago", delta.num_days())
    } else {
        // stable + readable
        t.format("%Y-%m-%d").to_string()
    }
}

/* ---------------- Auth ---------------- */

async fn index(State(st): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    let u = current_user(&st.db, &cookies).await;
    render_ok(IndexTemplate {
        logged_in: u.is_some(),
        username: u.map(|x| x.username).unwrap_or_default(),
    })
}

async fn register_page() -> impl IntoResponse {
    render_ok(RegisterTemplate)
}

#[derive(Deserialize)]
struct RegisterForm {
    username: String,
    email: String,
    password: String,
}

async fn register_post(
    State(st): State<AppState>,
    cookies: Cookies,
    Form(f): Form<RegisterForm>,
) -> impl IntoResponse {
    let hash = match auth::hash_password(&f.password) {
        Ok(h) => h,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad password").into_response(),
    };

    let res = sqlx::query(
        r#"
        insert into users (username, email, password_hash)
        values ($1, $2, $3)
        returning id
        "#,
    )
    .bind(&f.username)
    .bind(&f.email)
    .bind(&hash)
    .fetch_one(&st.db)
    .await;

    let row = match res {
        Ok(r) => r,
        Err(_) => return (StatusCode::CONFLICT, "username/email taken").into_response(),
    };

    let user_id: i64 = row.get("id");
    set_session(&cookies, user_id);
    Redirect::to("/").into_response()
}

async fn login_page() -> impl IntoResponse {
    render_ok(LoginTemplate)
}

#[derive(Deserialize)]
struct LoginForm {
    login: String,
    password: String,
}

async fn login_post(
    State(st): State<AppState>,
    cookies: Cookies,
    Form(f): Form<LoginForm>,
) -> impl IntoResponse {
    let res = sqlx::query(
        r#"
        select id, password_hash
        from users
        where username = $1 or email = $1
        "#,
    )
    .bind(&f.login)
    .fetch_optional(&st.db)
    .await;

    let row = match res {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "bad credentials").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    let user_id: i64 = row.get("id");
    let password_hash: String = row.get("password_hash");

    let ok = auth::verify_password(&f.password, &password_hash).unwrap_or(false);
    if !ok {
        return (StatusCode::UNAUTHORIZED, "bad credentials").into_response();
    }

    set_session(&cookies, user_id);
    Redirect::to("/").into_response()
}

async fn logout_post(cookies: Cookies) -> impl IntoResponse {
    cookies.remove(Cookie::from("session"));
    Redirect::to("/").into_response()
}

/* ---------------- Poems ---------------- */

#[derive(Clone)]
struct PoemListItem {
    id: i64,
    title: String,
    author: String,
    published_at: Option<String>,
}

async fn poems_list(State(st): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    let u = current_user(&st.db, &cookies).await;

    let rows = sqlx::query(
        r#"
        select p.id, p.title, u.username as author, p.published_at
        from poems p
        join users u on u.id = p.author_id
        where p.status = 'published'
        order by p.published_at desc nulls last, p.id desc
        "#,
    )
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();

    let poems = rows
        .into_iter()
        .map(|r| PoemListItem {
            id: r.get("id"),
            title: r.get("title"),
            author: r.get("author"),
            published_at: r
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("published_at")
                .ok()
                .flatten()
                .map(|dt| dt.to_rfc3339()),
        })
        .collect();

    render_ok(PoemsListTemplate {
        logged_in: u.is_some(),
        username: u.map(|x| x.username).unwrap_or_default(),
        poems,
    })
}

async fn poem_new_page(State(st): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    let u = match current_user(&st.db, &cookies).await {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };

    render_ok(PoemNewTemplate {
        logged_in: true,
        username: u.username,
    })
}

#[derive(Deserialize)]
struct PoemForm {
    title: String,
    body: String,
}

async fn poem_create(
    State(st): State<AppState>,
    cookies: Cookies,
    Form(f): Form<PoemForm>,
) -> impl IntoResponse {
    let u = match current_user(&st.db, &cookies).await {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };

    let row = sqlx::query(
        r#"
        insert into poems (author_id, title, body, status)
        values ($1, $2, $3, 'draft')
        returning id
        "#,
    )
    .bind(u.id)
    .bind(&f.title)
    .bind(&f.body)
    .fetch_one(&st.db)
    .await;

    let row = match row {
        Ok(r) => r,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    let id: i64 = row.get("id");
    Redirect::to(&format!("/poems/{id}")).into_response()
}

#[derive(Clone)]
struct PoemView {
    id: i64,
    title: String,
    body: String,
    author: String,
    author_id: i64,
    status: String,
}

async fn poem_view(
    State(st): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let u = current_user(&st.db, &cookies).await;

    let row = sqlx::query(
        r#"
        select p.id, p.title, p.body, p.status, p.author_id, u.username as author
        from poems p
        join users u on u.id = p.author_id
        where p.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await;

    let r = match row {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    let poem = PoemView {
        id: r.get("id"),
        title: r.get("title"),
        body: r.get("body"),
        status: r.get("status"),
        author_id: r.get("author_id"),
        author: r.get("author"),
    };

    if poem.status == "draft" {
        let allowed = u
            .as_ref()
            .map(|cu| cu.id == poem.author_id || is_admin_or_mod(cu))
            .unwrap_or(false);
        if !allowed {
            return (StatusCode::NOT_FOUND, "not found").into_response();
        }
    }

    let can_edit = u
        .as_ref()
        .map(|cu| cu.id == poem.author_id || is_admin_or_mod(cu))
        .unwrap_or(false);

    let comments = load_comments(&st.db, id).await.unwrap_or_default();

    render_ok(PoemViewTemplate {
        logged_in: u.is_some(),
        username: u.map(|x| x.username).unwrap_or_default(),
        poem,
        can_edit,
        comments,
    })
}

async fn poem_edit_page(
    State(st): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let cu = match current_user(&st.db, &cookies).await {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };

    let row = sqlx::query(
        r#"
        select p.id, p.title, p.body, p.status, p.author_id, u.username as author
        from poems p
        join users u on u.id = p.author_id
        where p.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await;

    let r = match row {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    let poem = PoemView {
        id: r.get("id"),
        title: r.get("title"),
        body: r.get("body"),
        status: r.get("status"),
        author_id: r.get("author_id"),
        author: r.get("author"),
    };

    let allowed = cu.id == poem.author_id || is_admin_or_mod(&cu);
    if !allowed {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    render_ok(PoemEditTemplate {
        logged_in: true,
        username: cu.username,
        poem,
    })
}

async fn poem_update(
    State(st): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(f): Form<PoemForm>,
) -> impl IntoResponse {
    let cu = match current_user(&st.db, &cookies).await {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };

    let row = sqlx::query("select author_id from poems where id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await;

    let r = match row {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    let author_id: i64 = r.get("author_id");
    if cu.id != author_id && !is_admin_or_mod(&cu) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    let res = sqlx::query(
        r#"
        update poems
        set title = $1,
            body = $2,
            updated_at = now()
        where id = $3
        "#,
    )
    .bind(&f.title)
    .bind(&f.body)
    .bind(id)
    .execute(&st.db)
    .await;

    if res.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }

    Redirect::to(&format!("/poems/{id}")).into_response()
}

async fn poem_publish(
    State(st): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let cu = match current_user(&st.db, &cookies).await {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };

    let row = sqlx::query("select author_id, status from poems where id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await;

    let r = match row {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    let author_id: i64 = r.get("author_id");
    let status: String = r.get("status");

    if cu.id != author_id && !is_admin_or_mod(&cu) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    if status != "draft" {
        return Redirect::to(&format!("/poems/{id}")).into_response();
    }

    let res = sqlx::query(
        r#"
        update poems
        set status = 'published',
            published_at = now(),
            updated_at = now()
        where id = $1
        "#,
    )
    .bind(id)
    .execute(&st.db)
    .await;

    if res.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }

    Redirect::to(&format!("/poems/{id}")).into_response()
}

async fn poem_delete(
    State(st): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let cu = match current_user(&st.db, &cookies).await {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };

    let row = sqlx::query("select author_id from poems where id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await;

    let r = match row {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    let author_id: i64 = r.get("author_id");
    if cu.id != author_id && !is_admin_or_mod(&cu) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    let _ = sqlx::query("delete from comments where poem_id = $1")
        .bind(id)
        .execute(&st.db)
        .await;

    let res = sqlx::query("delete from poems where id = $1")
        .bind(id)
        .execute(&st.db)
        .await;

    if res.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }

    Redirect::to("/poems").into_response()
}

#[derive(Clone)]
struct MyPoemItem {
    id: i64,
    title: String,
    status: String,
}

async fn my_drafts(State(st): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    let cu = match current_user(&st.db, &cookies).await {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };

    let rows = sqlx::query(
        r#"
        select id, title, status
        from poems
        where author_id = $1 and status = 'draft'
        order by updated_at desc, id desc
        "#,
    )
    .bind(cu.id)
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();

    let poems = rows
        .into_iter()
        .map(|r| MyPoemItem {
            id: r.get("id"),
            title: r.get("title"),
            status: r.get("status"),
        })
        .collect();

    render_ok(MyDraftsTemplate {
        logged_in: true,
        username: cu.username,
        poems,
    })
}

/* ---------------- Comments ---------------- */

#[derive(Clone)]
struct CommentView {
    author: String,
    body: String,
    created_at: chrono::DateTime<chrono::Utc>,
    time_ago: String,
}

#[derive(Deserialize)]
struct CommentForm {
    body: String,
    website: Option<String>, // honeypot
}

async fn load_comments(db: &PgPool, poem_id: i64) -> anyhow::Result<Vec<CommentView>> {
    let rows = sqlx::query(
        r#"
        select u.username as author, c.body, c.created_at
        from comments c
        join users u on u.id = c.author_id
        where c.poem_id = $1
          and c.is_deleted = false
          and c.is_spam = false
        order by c.created_at asc, c.id asc
        "#,
    )
    .bind(poem_id)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let created: chrono::DateTime<chrono::Utc> = r.get("created_at");
            CommentView {
                author: r.get("author"),
                body: r.get("body"),
                created_at: created,
                time_ago: time_ago(created),
            }
        })
        .collect())
}

async fn comment_add(
    State(st): State<AppState>,
    cookies: Cookies,
    Path(id): Path<i64>,
    Form(f): Form<CommentForm>,
) -> impl IntoResponse {
    let cu = match current_user(&st.db, &cookies).await {
        Some(u) => u,
        None => return Redirect::to("/login").into_response(),
    };

    // honeypot: if filled, pretend success
    if f.website.as_deref().unwrap_or("").trim().len() > 0 {
        return Redirect::to(&format!("/poems/{id}")).into_response();
    }

    // rate limit: max 3 comments / 30 seconds
    let recent_count = sqlx::query_scalar::<_, i64>(
        r#"
        select count(*)
        from comments
        where author_id = $1
          and created_at > now() - interval '30 seconds'
        "#,
    )
    .bind(cu.id)
    .fetch_one(&st.db)
    .await
    .unwrap_or(0);

    if recent_count >= 3 {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
    }

    let row = sqlx::query("select status, author_id from poems where id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await;

    let r = match row {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    let status: String = r.get("status");
    let author_id: i64 = r.get("author_id");

    if status != "published" && cu.id != author_id && !is_admin_or_mod(&cu) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    let body = f.body.trim();
    if body.is_empty() {
        return Redirect::to(&format!("/poems/{id}")).into_response();
    }

    // shadowban => silently mark as spam
    let shadowbanned = sqlx::query_scalar::<_, bool>(
        "select is_shadowbanned from users where id = $1",
    )
    .bind(cu.id)
    .fetch_one(&st.db)
    .await
    .unwrap_or(false);

    let res = sqlx::query(
        r#"
        insert into comments (poem_id, author_id, body, is_spam)
        values ($1, $2, $3, $4)
        "#,
    )
    .bind(id)
    .bind(cu.id)
    .bind(body)
    .bind(shadowbanned)
    .execute(&st.db)
    .await;

    if res.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }

    Redirect::to(&format!("/poems/{id}")).into_response()
}
