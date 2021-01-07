# A OpenID Connect Spy for Gitlab

If you want to modify some data of Gitlab OpenID Connect result like add new fields or change some value.

This program was written in Rust, you may need to change some configurations in the config.rs file and compile this whole project before deploy.

## What happen it

- `sub`: Will change the sub from email address prefix
- `iss`: Will replace the value with configuration
- `username`: Add new field from email address prefix

That all the other fields leave it default.

## Config

Just simple two item

- `gitlab_url`: Gitlab server URL 
- `iss_url`: Replace the gitlab url when response the result iss field from Gitlab server
