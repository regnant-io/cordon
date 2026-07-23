//! Cordon Web UI -- embedded HTML pages served at /ui/*
#![allow(missing_docs)]

use axum::{extract::State, response::Html};
use crate::handlers::AppState;

pub async fn ui_landing(State(state): State<AppState>) -> Html<String> {
    let node = &state.node;
    let ns = node.state.read();
    let status = ns.status.to_string();
    drop(ns);
    let pill = if status == "operational" { "pill-g" } else { "pill-y" };
    let pill_dot = if status == "operational" { "" } else { "warn" };
    let badge_class = if status == "operational" { "green" } else { "yellow" };
    let backend = node.inference.backend_name().to_string();
    let mrenclave = node.attestation.mrenclave();
    let tee = node.config.tee.preferred.to_string();
    let node_id = node.config.node_id.clone();
    let version = env!("CARGO_PKG_VERSION");

    let html = include_str!("../../../ui/landing_template.html")
        .replace("{VERSION}", version)
        .replace("{PILL}", pill)
        .replace("{PILL_DOT}", pill_dot)
        .replace("{BADGE_CLASS}", badge_class)
        .replace("{STATUS}", &status)
        .replace("{TEE}", &tee)
        .replace("{BACKEND}", &backend)
        .replace("{NODE_ID}", &node_id)
        .replace("{MRENCLAVE}", &mrenclave);
    Html(html)
}

pub async fn ui_chat() -> Html<&'static str> {
    Html(include_str!("../../../ui/chat.html"))
}

pub async fn ui_endpoints() -> Html<&'static str> {
    Html(include_str!("../../../ui/endpoints.html"))
}

pub async fn ui_docs() -> Html<&'static str> {
    Html(include_str!("../../../ui/docs.html"))
}
