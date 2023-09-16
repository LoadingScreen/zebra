#![allow(non_snake_case)]

use dioxus::prelude::*;

fn main() {
    dioxus_desktop::launch(App);
}

fn App(cx: Scope) -> Element {
    cx.render(rsx! {
        title { "Spartacus" }
        section {
            class: "spartacus",
            style { include_str!("style.css") }
            TabSelect {}
            div {
                class: "contents",
                About {}
            }
        }
    })
}

fn TabSelect(cx: Scope) -> Element {
    cx.render(rsx! {
        nav {
            class: "tab_select",
            div {
                class: "tab_choice inactive_tab",
                "My Keys"
            }
            div {
                class: "tab_choice inactive_tab",
                "Other Keys"
            }
            div {
                class: "tab_choice inactive_tab",
                "Sign"
            }
            div {
                class: "tab_choice inactive_tab",
                "Verify"
            }
            div {
                class: "tab_choice active_tab",
                "About"
            }
        }
    })
}

fn About(cx: Scope) -> Element {
    cx.render(rsx! {
        div {
            class: "about",
            h1 {"Spartacus"}
            p {"A tool for ring signatures."}
            p {"Version 0.0.0"}
        }
    })
}
