use actix_web::{web, App, HttpServer, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use log::{error};
use std::error;
use base64_url;
use std::str::from_utf8;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

mod config;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize, Serialize, Debug)]
struct QueryInfo {
  response_type: String,
  client_id: String,
  redirect_uri: String,
  scope: String,
  state: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct QueryUser {
  access_token: String,
}

#[derive(Deserialize, Serialize)]
struct PostInfo {
  grant_type: String,
  client_id: String,
  client_secret: String,
  code: String,
  redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
  iss: String,         // Optional. Issuer
  sub: String,         // Optional. Subject (whom token refers to)
  aud: String,         // Optional. Audience
  exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
  iat: usize,          // Optional. Issued at (as UTC timestamp)
  email: String,
  email_verified: bool,
  auth_time: usize,
  sub_legacy: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NewClaims {
  iss: String,         // Optional. Issuer
  sub: String,         // Optional. Subject (whom token refers to)
  aud: String,         // Optional. Audience
  exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
  iat: usize,          // Optional. Issued at (as UTC timestamp)
  email: String,
  email_verified: bool,
  auth_time: usize,
  sub_legacy: String,
  username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JWTHeader {
  alg: String,
  kid: String,
}

#[derive(Serialize, Deserialize)]
struct UserInfo {
  sub: String,
  sub_legacy: String,
  name: String,
  nickname: String,
  email: String,
  email_verified: bool,
  profile: String,
  picture: String,
  groups: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct NewUserInfo {
  sub: String,
  name: String,
  username: String,
  email: String,
  email_verified: bool,
  profile: String,
  picture: String,
  groups: Vec<String>,
}

fn internal_error() -> HttpResponse {
  HttpResponse::InternalServerError()
    .content_type("plain/text")
    .body("Internal Service  Error")
}

async fn stage1(info: web::Query<QueryInfo>) -> HttpResponse {
  let uri = format!(
    "https://git.uinnova.com/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}",
    client_id = info.client_id,
    redirect_uri = info.redirect_uri,
    scope = info.scope,
    state = info.state,
  );

  HttpResponse::TemporaryRedirect()
    .header(http::header::LOCATION, uri)
    .finish()
}

async fn stage2(info: web::Json<PostInfo>) -> HttpResponse {
  let uri = "https://git.uinnova.com/oauth/token";

  let client = reqwest::Client::new();

  let mut params = HashMap::new();
  params.insert("grant_type", info.grant_type.to_owned());
  params.insert("client_id", info.client_id.to_owned());
  params.insert("client_secret", info.client_secret.to_owned());
  params.insert("code", info.code.to_owned());
  params.insert("redirect_uri", info.redirect_uri.to_owned());

  let resp = match client.post(uri).json(&params).send().await {
    Ok(res) => res,
    Err(e) =>  {
      error!("ERROR: {}", e);
      return internal_error()
    }
  };

  let status = resp.status();
  let body = match resp.text().await {
    Ok(t) => t,
    Err(e) => {
      error!("ERROR: {}", e);
      return internal_error()
    }
  };

  if status == http::StatusCode::OK {
    let mut body_json: serde_json::Value = match serde_json::from_str(&body) {
      Ok(r) => r,
      Err(e) => {
        error!("ERROR: {}", e);
        return internal_error()
      }
    };
  
    let id_token = match body_json["id_token"].as_str() {
      Some(t) => t,
      None => {
        error!("ERROR: Missing id_token feild");
        return internal_error()
      }
    };
  
    let new_id_token = match jwt_inject(id_token.to_string()) {
      Ok(t) => t,
      Err(e) => {
        error!("ERROR: {}", e);
        return internal_error()
      }
    };

    body_json["id_token"] = serde_json::Value::String(new_id_token);

    let new_body = body_json.to_string();
  
    HttpResponse::Ok()
      .header(http::header::CONTENT_TYPE, "application/json")
      .header(http::header::CONTENT_LENGTH, new_body.len())
      .body(new_body)
  } else {
    HttpResponse::build(status)
      .header(http::header::CONTENT_TYPE, "application/json")
      .header(http::header::CONTENT_LENGTH, body.len())
      .body(body)
  }
}

async fn stage3(info: web::Query<QueryUser>) -> HttpResponse {
  let uri = format!(
    "https://git.uinnova.com/oauth/userinfo?access_token={access_token}",
    access_token = info.access_token,
  );

  let resp = match reqwest::get(&uri).await {
    Ok(r) => r,
    Err(e) => {
      error!("ERROR: {}", e);
      return internal_error()
    }
  };

  let status = resp.status();
  let body = match resp.text().await {
    Ok(t) => t,
    Err(e) => {
      error!("ERROR: {}", e);
      return internal_error()
    }
  };

  if status == http::StatusCode::OK {

    let user_info: UserInfo = serde_json::from_str(&body).unwrap();
    let email_split:Vec<&str> = user_info.email.split("@").collect();
    let new_user_info = NewUserInfo {
      sub: email_split[0].to_owned(),
      name: user_info.name,
      username: email_split[0].to_owned(),
      email: user_info.email,
      email_verified: user_info.email_verified,
      profile: user_info.profile,
      picture: user_info.picture,
      groups: user_info.groups,
    };

    let new_body = serde_json::to_string(&new_user_info).unwrap();

    HttpResponse::Ok()
      .header(http::header::CONTENT_TYPE, "application/json")
      .header(http::header::CONTENT_LENGTH, new_body.len())
      .body(new_body)
  } else {
    HttpResponse::build(status)
      .header(http::header::CONTENT_TYPE, "application/json")
      .header(http::header::CONTENT_LENGTH, body.len())
      .body(body)
  }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  env_logger::init();
  HttpServer::new(|| {
    App::new().service(
      web::scope("/oauth")
      .route("/authorize", web::get().to(stage1))
      .route("/token", web::post().to(stage2))
      .route("/userinfo", web::get().to(stage3))
    )
  })
  .bind("0.0.0.0:80")?
  .run()
  .await
}

fn jwt_inject(id_token: String) -> Result<String> {
  let split: Vec<&str> = id_token.split(".").collect();
  let claims_json = base64_url::decode(split[1])?;

  let claims: Claims = serde_json::from_str(&from_utf8(&claims_json).unwrap())?;

  let email_split:Vec<&str> = claims.email.split("@").collect();

  let new_claims = NewClaims {
    iss: "https://auth.udolphin.com".to_string(),
    sub: email_split[0].to_owned(),
    aud: claims.aud, 
    exp: claims.exp, 
    iat: claims.iat,
    email: claims.email.to_owned(),
    email_verified: claims.email_verified,
    auth_time: claims.auth_time,
    sub_legacy: claims.sub_legacy,
    username: email_split[0].to_owned(),
  };

  let claims_json_new = base64_url::encode(serde_json::to_string(&new_claims)?.as_bytes());
  let header = base64_url::decode(split[0])?;
  let claims_header: JWTHeader = serde_json::from_str(from_utf8(&header).unwrap())?;

  let mut signature = match HmacSha256::new_varkey(claims_header.kid.as_bytes()) {
    Ok(s) => s,
    Err(_) => {
      return Err("Invalid Key Length")?;
    }
  };

  let new_sign = format!(
    "{header}.{payload}",
    // secret = claims_header.kid,
    header = split[0],
    payload = claims_json_new
  );
  
  signature.update(new_sign.as_bytes());
  let mac_result = signature.finalize();

  Ok(format!(
    "{header}.{payload}.{signature}",
    header = split[0],
    payload = claims_json_new,
    signature = base64_url::encode(&mac_result.into_bytes())
  ))
}
