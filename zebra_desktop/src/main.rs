#![allow(non_snake_case)]
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use copypasta::{ClipboardContext, ClipboardProvider};
use dioxus::prelude::*;
use dioxus_desktop::WindowBuilder;
use dioxus_free_icons::{
    icons::go_icons::{
        GoCheck, GoCopy, GoPlusCircle, GoSearch, GoShieldCheck, GoShieldLock, GoTrash, GoUnverified,
        GoVerified,
    },
    Icon,
};

use boringascii::BoringAscii;
use zebra::about::About;
use zebra_crypto::{PublicKey, SignatureParseError, SignedMessage};
use zebra_storage::{default_db_path, Database, VerificationInfo};

fn make_config() -> dioxus_desktop::Config {
    dioxus_desktop::Config::default().with_window(
        WindowBuilder::new()
            .with_title("ZebraSign")
            .with_min_inner_size(dioxus_desktop::tao::dpi::Size::Logical(
                dioxus_desktop::tao::dpi::LogicalSize {
                    width: 900.0,
                    height: 600.0,
                },
            )),
    )
}

fn main() {
    #[cfg(not(feature = "debug"))]
    // This is overkill, but also cheap.
    if let Err(e) = secmem_proc::harden_process() {
        eprintln!("Error: Could not harden process; exiting. {e}");
        return;
    }
    dioxus_desktop::launch::launch(App, vec![], make_config());
}

#[derive(Clone, Copy, Debug)]
enum ActiveTab {
    MyKeys,
    OtherKeys,
    Sign,
    Verify,
    About,
    Danger,
}

struct NewPrivateName(String);
struct NewPrivateEmail(BoringAscii);
struct TextToSign(String);
/// None is "there was no message pasted" and "Err(e)" is "the message failed to parse"
struct MessageToVerify(Option<Result<SignedMessage, SignatureParseError>>);
struct SelectedPrivateSigner(Option<PublicKey>);
struct SelectedPublicSigners(BTreeSet<PublicKey>);
/// None is "there was no key imported" and "Err(e)" is "the key failed to import"
struct ImportKeyResult(Option<Result<(), String>>);
struct CopiedToClipboard(Option<PublicKey>);
struct SignAndCopyStatus(bool);

#[derive(Clone)]
struct TableFilter {
    name: String,
    email: String,
    fingerprint: String,
}

struct PrivateFilter(TableFilter);
struct PublicFilter(TableFilter);
struct SignerFilter(TableFilter);
struct DangerFilter(TableFilter);

trait Filter {
    fn set_name(&mut self, name: &str);
    fn set_email(&mut self, email: &str);
    fn set_fingerprint(&mut self, fingerprint: &str);
}

impl Filter for PrivateFilter {
    fn set_name(&mut self, name: &str) {
        self.0.name = name.to_string();
    }

    fn set_email(&mut self, email: &str) {
        self.0.email = email.to_string();
    }

    fn set_fingerprint(&mut self, fingerprint: &str) {
        self.0.fingerprint = fingerprint.to_string();
    }
}

impl Filter for PublicFilter {
    fn set_name(&mut self, name: &str) {
        self.0.name = name.to_string();
    }

    fn set_email(&mut self, email: &str) {
        self.0.email = email.to_string();
    }

    fn set_fingerprint(&mut self, fingerprint: &str) {
        self.0.fingerprint = fingerprint.to_string();
    }
}

impl Filter for SignerFilter {
    fn set_name(&mut self, name: &str) {
        self.0.name = name.to_string();
    }

    fn set_email(&mut self, email: &str) {
        self.0.email = email.to_string();
    }

    fn set_fingerprint(&mut self, fingerprint: &str) {
        self.0.fingerprint = fingerprint.to_string();
    }
}

impl Filter for DangerFilter {
    fn set_name(&mut self, name: &str) {
        self.0.name = name.to_string();
    }

    fn set_email(&mut self, email: &str) {
        self.0.email = email.to_string();
    }

    fn set_fingerprint(&mut self, fingerprint: &str) {
        self.0.fingerprint = fingerprint.to_string();
    }
}

fn App() -> Element {
    let desktop = dioxus_desktop::use_window();
    desktop.set_title("ZebraSign");

    use_context_provider(|| Signal::new(ActiveTab::MyKeys));
    use_context_provider(|| Signal::new(NewPrivateName(String::new())));
    use_context_provider(|| Signal::new(NewPrivateEmail(BoringAscii::default())));
    use_context_provider(|| Signal::new(TextToSign(String::new())));
    use_context_provider(|| Signal::new(MessageToVerify(None)));
    use_context_provider(|| Signal::new(SelectedPublicSigners(BTreeSet::new())));
    use_context_provider(|| Signal::new(CopiedToClipboard(None)));
    use_context_provider(|| Signal::new(SignAndCopyStatus(false)));
    use_context_provider(|| {
        Signal::new(SignerFilter(TableFilter {
            name: String::new(),
            email: String::new(),
            fingerprint: String::new(),
        }))
    });
    use_context_provider(|| {
        Signal::new(PrivateFilter(TableFilter {
            name: String::new(),
            email: String::new(),
            fingerprint: String::new(),
        }))
    });
    use_context_provider(|| {
        Signal::new(PublicFilter(TableFilter {
            name: String::new(),
            email: String::new(),
            fingerprint: String::new(),
        }))
    });
    use_context_provider(|| {
        Signal::new(DangerFilter(TableFilter {
            name: String::new(),
            email: String::new(),
            fingerprint: String::new(),
        }))
    });

    let db = Database::new(default_db_path());

    use_context_provider(|| {
        Signal::new(SelectedPrivateSigner({
            if let Ok(ref d) = db {
                d.visible_contents.my_public_keys.iter().next().cloned()
            } else {
                None
            }
        }))
    });

    use_context_provider(|| Signal::new(db));
    use_context_provider(|| Signal::new(ImportKeyResult(None)));

    let style = include_str!("style.css");

    rsx! {
        div {
            class: "zebra",
            style { {style} }
            TabSelect {}
            div {
                class: "contents",
                {
                    match *use_context::<Signal<ActiveTab>>().read() {
                        ActiveTab::MyKeys => rsx! { MyKeys {} },
                        ActiveTab::OtherKeys => rsx! { OtherKeys {} },
                        ActiveTab::Sign => rsx! { Sign {} },
                        ActiveTab::Verify => rsx! { Verify {} },
                        ActiveTab::About => rsx! { About {} },
                        ActiveTab::Danger => rsx! { Danger {} },
                    }
                }
            }
        }
    }
}

fn TabSelect() -> Element {
    let desktop = dioxus_desktop::use_window();
    let active_tab = *use_context::<Signal<ActiveTab>>().read();
    rsx! {
        nav {
            onmousedown: move |_| { desktop.drag(); },
            class: "tab_select",
            div {
                onclick: move |_| {*use_context::<Signal<ActiveTab>>().write() = ActiveTab::MyKeys},
                class: {
                    if let ActiveTab::MyKeys = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                "My Keypairs"
            }
            div {
                onclick: move |_| {*use_context::<Signal<ActiveTab>>().write() = ActiveTab::OtherKeys},
                class: {
                    if let ActiveTab::OtherKeys = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                "Other Keys"
            }
            div {
                onclick: move |_| {*use_context::<Signal<ActiveTab>>().write() = ActiveTab::Sign},
                class: {
                    if let ActiveTab::Sign = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                "Sign"
            }
            div {
                onclick: move |_| {*use_context::<Signal<ActiveTab>>().write() = ActiveTab::Verify},
                class: {
                    if let ActiveTab::Verify = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                "Verify"
            }
            div {
                onclick: move |_| {*use_context::<Signal<ActiveTab>>().write() = ActiveTab::About},
                class: {
                    if let ActiveTab::About = active_tab {
                        "tab_choice active_tab"
                    } else {
                        "tab_choice inactive_tab"
                    }
                },
                "About"
            }
            div {
                onclick: move |_| {*use_context::<Signal<ActiveTab>>().write() = ActiveTab::Danger},
                class: {
                    if let ActiveTab::Danger = active_tab {
                        "tab_choice danger_tab active_tab"
                    } else {
                        "tab_choice danger_tab inactive_tab"
                    }
                },
                "Danger"
            }
        }
    }
}

#[derive(Clone, PartialEq, Props)]
struct DeleteButtonProps {
    k: PublicKey,
    private: bool,
}

fn DeleteButton(props: DeleteButtonProps) -> Element {
    let mut dbresult = use_context::<Signal<std::io::Result<Database>>>();
    let mut selected_private_signer = use_context::<Signal<SelectedPrivateSigner>>();
    let mut selected_public_signers = use_context::<Signal<SelectedPublicSigners>>();
    rsx! {
        a {
            class: "delete_button action_button",
            href: "",
            onclick: {
                move |e| {
                    e.stop_propagation();
                    match dbresult.write().deref_mut() {
                        Ok(ref mut db) => {
                            if props.private {
                                let _ = db.delete_private_key(&props.k);
                                let mut private_signer_write = selected_private_signer.write();
                                let private_signer = private_signer_write.deref_mut();
                                if private_signer.0 == Some(props.k.clone()) {
                                    *private_signer = SelectedPrivateSigner(db.visible_contents.my_public_keys.iter().next().cloned());
                                }
                            } else {
                                let _ = db.delete_public_key(&props.k);
                                let mut public_signer_write = selected_public_signers.write();
                                let public_signer = public_signer_write.deref_mut();
                                public_signer.0.remove(&props.k);
                            }
                        }
                        Err(_e) => {}
                    }
                }
            },
            Icon {
                width: 15,
                height: 15,
                fill: "#cc3333",
                icon: GoTrash,
            }
        }
    }
}

#[derive(Clone, PartialEq, Props)]
struct VerifyButtonProps {
    k: PublicKey,
    verif: VerificationInfo,
}

fn VerifyButton(props: VerifyButtonProps) -> Element {
    let mut dbresult = use_context::<Signal<std::io::Result<Database>>>();
    if let Some(t) = props.verif.verified_time() {
        rsx! {
            a {
                class: "action_button",
                href: "",
                title: "Verified {t.date()}",
                onclick: {
                    move |e| {
                        e.stop_propagation();
                        match dbresult.write().deref_mut() {
                            Ok(ref mut db) => {
                                let _ = db.set_unverified(&props.k);
                            }
                            Err(_e) => {}
                        }
                    }
                },
                Icon {
                    width: 15,
                    height: 15,
                    fill: "#00f",
                    icon: GoVerified,
                }
            }
        }
    } else {
        rsx! {
            a {
                class: "action_button",
                href: "",
                title: "This key is unverified",
                onclick: {
                    move |e| {
                        e.stop_propagation();
                        match dbresult.write().deref_mut() {
                            Ok(ref mut db) => {
                                let _ = db.set_verified(&props.k);
                            }
                            Err(_e) => {}
                        }
                    }
                },
                Icon {
                    width: 15,
                    height: 15,
                    fill: "#999",
                    icon: GoUnverified,
                }
            }
        }
    }
}

fn FilterRow<T: Filter + 'static>() -> Element {
    let mut filter = use_context::<Signal<T>>();

    rsx! {
        tr {
            class: "filter_row",
            td {
                class: "name",
                input {
                    "type": "text",
                    placeholder: "Filter names",
                    oninput: move |evt| filter.write().set_name(&evt.value())
                }
                Icon {
                    class: "search_icon",
                    width: 16,
                    height: 16,
                    fill: "black",
                    icon: GoSearch,
                }
            }
            td {
                class: "email",
                input {
                    "type": "text",
                    placeholder: "Filter emails",
                    oninput: move |evt| filter.write().set_email(&evt.value())
                }
                Icon {
                    class: "search_icon",
                    width: 16,
                    height: 16,
                    fill: "black",
                    icon: GoSearch,
                }
            }
            td {
                class: "fingerprint",
                input {
                    "type": "text",
                    placeholder: "Filter fingerprints",
                    oninput: move |evt| filter.write().set_fingerprint(&evt.value())
                }
                Icon {
                    class: "search_icon",
                    width: 16,
                    height: 16,
                    fill: "black",
                    icon: GoSearch,
                }
            }
            td {
                class: "delete"
            }
        }
    }
}

fn Danger() -> Element {
    let dbresult = use_context::<Signal<std::io::Result<Database>>>();
    let dbread = dbresult.read();
    let keys = match dbread.deref() {
        Ok(ref db) => db.visible_contents.my_public_keys.clone(),
        Err(ref e) => {
            return rsx! {
                "Error reading database: {e}"
            }
        }
    };
    let filter = use_context::<Signal<DangerFilter>>();

    let filter_name = filter.read().0.name.to_lowercase();
    let filter_email = filter.read().0.email.to_lowercase();
    let filter_fingerprint = filter.read().0.fingerprint.replace(' ', "").to_lowercase();

    rsx! {
        div {
            class: "toolbar",
            "WARNING: The actions on this tab are irreversible!"
        }
        div {
            class: "data",
            table {
                class: "mykeys",
                thead {
                    FilterRow::<DangerFilter> {}
                }
                thead {
                    tr {
                        th {
                            "Name"
                        }
                        th {
                            "Email"
                        }
                        th {
                            "Fingerprint"
                        }
                        th {
                            "Actions"
                        }
                    }
                }
                tbody {
                    for k in keys.into_iter() {
                        if k.holder().name().to_lowercase().contains(&filter_name)
                            && k.holder().email().to_lowercase().contains(&filter_email)
                            && k.fingerprint().replace(' ', "").to_lowercase().contains(&filter_fingerprint)
                        {
                            tr {
                                key: "{k.fingerprint()}",
                                td {
                                    class: "name",
                                    {k.holder().name().clone()},
                                }
                                td {
                                    class: "email",
                                    {k.holder().email().as_str().to_string()},
                                }
                                td {
                                    class: "fingerprint",
                                    {k.fingerprint()}
                                }
                                td {
                                    class: "delete",
                                    DeleteButton {
                                        k: k.clone(),
                                        private: true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn MyKeys() -> Element {
    let mut dbresult = use_context::<Signal<std::io::Result<Database>>>();
    let dbread = dbresult.read();
    let mut new_private_name = use_context::<Signal<NewPrivateName>>();
    let new_private_name_val = new_private_name.read().deref().0.clone();
    let new_private_name_copy = new_private_name.read().deref().0.clone();
    let mut new_private_email = use_context::<Signal<NewPrivateEmail>>();
    let new_private_email_val = new_private_email.read().deref().0.clone();
    let new_private_email_copy = new_private_email.read().deref().0.clone();
    let mut selected_private_signer = use_context::<Signal<SelectedPrivateSigner>>();
    let mut copied_to_clipboard = use_context::<Signal<CopiedToClipboard>>();
    let keys = match dbread.deref() {
        Ok(ref db) => db.visible_contents.my_public_keys.clone(),
        Err(ref e) => {
            return rsx! {
                "Error reading database: {e}"
            }
        }
    };

    let new_key_form_id = "new_key_form";

    let filter = use_context::<Signal<PrivateFilter>>();

    let filter_name = filter.read().0.name.to_lowercase();
    let filter_email = filter.read().0.email.to_lowercase();
    let filter_fingerprint = filter.read().0.fingerprint.replace(' ', "").to_lowercase();

    rsx! {
        form {
            onsubmit: move |_| {
                match dbresult.write().deref_mut() {
                    Ok(ref mut db) => {
                        if let Ok(email) = BoringAscii::from_str(&new_private_email_copy) {
                            if let Ok(()) = db.new_private_key(&new_private_name_copy, &email) {
                                *new_private_name.write() = NewPrivateName("".to_string());
                                *new_private_email.write() = NewPrivateEmail(BoringAscii::default());
                                let mut selected_private_signer_write = selected_private_signer.write();
                                if selected_private_signer_write.deref().0.is_none() {
                                    *selected_private_signer_write = SelectedPrivateSigner(db.visible_contents.my_public_keys.iter().next().cloned());

                                }
                            }
                        }
                    }
                    Err(_e) => {}
                }
            },
            id: new_key_form_id
        }
        div {
            class: "toolbar",
            Icon {
                class: "action_icon",
                width: 15,
                height: 15,
                fill: "black",
                icon: GoPlusCircle,
            }
            input {
                class: "new_key_name_input",
                value: "{new_private_name_val}",
                placeholder: "New Key Name",
                form: new_key_form_id,
                oninput: move |evt| *new_private_name.write() = NewPrivateName(evt.value().clone())
            }
            input {
                class: "new_key_email_input",
                value: "{new_private_email_val}",
                placeholder: "New Key Email",
                form: new_key_form_id,
                oninput: move |evt| {
                    if let Ok(new) = BoringAscii::from_str(&evt.value()) {
                        *new_private_email.write() = NewPrivateEmail(new)
                    } else {
                        *new_private_email.write() = NewPrivateEmail(new_private_email_val.clone())
                    }
                }
            }
            input {
                "type": "submit",
                form: new_key_form_id,
                value: "Create New Keypair",
            }
        }
        div {
            class: "data",
            table {
                class: "mykeys",
                thead {
                    tr {
                        th {
                            "Name"
                        }
                        th {
                            "Email"
                        }
                        th {
                            "Fingerprint"
                        }
                        th {
                            "Actions"
                        }
                    }
                }
                tbody {
                    FilterRow::<PrivateFilter> {}
                    for k in keys.into_iter() {
                        if k.holder().name().to_lowercase().contains(&filter_name)
                            && k.holder().email().to_lowercase().contains(&filter_email)
                            && k.fingerprint().replace(' ', "").to_lowercase().contains(&filter_fingerprint)
                        {
                                tr {
                                    key: "{k.fingerprint()}",
                                    td {
                                        class: "name",
                                        {k.holder().name().clone()},
                                    }
                                    td {
                                        class: "email",
                                        {k.holder().email().as_str().to_string()},
                                    }
                                    td {
                                        class: "fingerprint",
                                        {k.fingerprint()}
                                    }
                                    td {
                                        class: "actions",
                                        a {
                                            href: "",
                                            title: "Copy Public Key",
                                            class: "action_button",
                                            onclick: {
                                                let k_copy = k.clone();
                                                move |e| {
                                                    e.stop_propagation();
                                                    if let Ok(mut ctx) = ClipboardContext::new() {
                                                        if ctx.set_contents(k_copy.clone().into()).is_ok() {
                                                            *copied_to_clipboard.write() = CopiedToClipboard(Some(k_copy.clone()));
                                                        }
                                                    }
                                                }
                                            },
                                            Icon {
                                                width: 15,
                                                height: 15,
                                                fill: "black",
                                                icon: GoCopy,
                                            }
                                            if copied_to_clipboard.read().0 == Some(k.clone()) {
                                                Icon {
                                                    width: 15,
                                                    height: 15,
                                                    fill: "green",
                                                    icon: GoCheck,
                                                }
                                            }
                                        }
                                    }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn OtherKeys() -> Element {
    let mut dbresult = use_context::<Signal<std::io::Result<Database>>>();
    let dbread = dbresult.read();
    let keys = match dbread.deref() {
        Ok(ref db) => db.visible_contents.their_public_keys.clone(),
        Err(ref e) => {
            return rsx! {
                "Error reading database: {e}"
            }
        }
    };

    let filter = use_context::<Signal<PublicFilter>>();
    let mut import_key_result = use_context::<Signal<ImportKeyResult>>();
    let mut copied_to_clipboard = use_context::<Signal<CopiedToClipboard>>();

    let filter_name = filter.read().0.name.to_lowercase();
    let filter_email = filter.read().0.email.to_lowercase();
    let filter_fingerprint = filter.read().0.fingerprint.replace(' ', "").to_lowercase();

    rsx! {
        div {
            class: "toolbar",
            Icon {
                class: "action_icon",
                width: 15,
                height: 15,
                fill: "black",
                icon: GoPlusCircle,
            }
            button {
                onclick: move |_| {
                    let mut import_result = import_key_result.write();
                    if let Ok(ref mut db) = dbresult.write().deref_mut() {
                        if let Ok(mut ctx) = ClipboardContext::new() {
                            if let Ok(contents) = ctx.get_contents() {
                                let mut to_import = vec![];
                                for line in contents.split('\n') {
                                    if let Ok(key) = PublicKey::from_str(line) {
                                        to_import.push(key)
                                    } else {
                                        *import_result = ImportKeyResult(Some(Err("Failed to parse key".to_string())));
                                        return;
                                    }
                                }
                                let _ = db.add_public_keys(&to_import);
                                *import_result = ImportKeyResult(Some(Ok(())));
                            } else {
                                *import_result = ImportKeyResult(Some(Err("Failed to get contents from clipboard".to_string())));
                            }
                        } else {
                            *import_result = ImportKeyResult(Some(Err("Failed to create clipboard context".to_string())));
                        }
                    } else {
                        *import_result = ImportKeyResult(Some(Err("Failed to access database".to_string())));
                    }
                },
                "Import Public Key from Clipboard"
            }
        },
        {
            if let Some(Err(e)) = import_key_result.read().0.clone() {
                rsx! {
                    div {
                        class: "data",
                        style: "height: 100px;",
                        "Error: {e}"
                    }
                }
            } else {
                rsx! { "" }
            }
        },
        div {
            class: "data",
            table {
                class: "otherkeys",
                thead {
                    tr {
                        th {
                            "Name"
                        }
                        th {
                            "Email"
                        }
                        th {
                            "Fingerprint"
                        }
                        th {
                            "Actions"
                        }
                    }
                }
                tbody {
                    FilterRow::<PublicFilter> {}
                    for k in keys.into_iter() {
                        if k.0.holder().name().to_lowercase().contains(&filter_name)
                            && k.0.holder().email().to_lowercase().contains(&filter_email)
                            && k.0.fingerprint().replace(' ', "").to_lowercase().contains(&filter_fingerprint)
                        {
                                tr {
                                    key: "{k.0.fingerprint()}",
                                    td {
                                        class: "name",
                                        {k.0.holder().name().clone()},
                                    }
                                    td {
                                        class: "email",
                                        {k.0.holder().email().as_str().to_string()},
                                    }
                                    td {
                                        class: "fingerprint",
                                        {k.0.fingerprint()}
                                    }
                                    td {
                                        class: "actions",
                                        VerifyButton {
                                            k: k.0.clone(),
                                            verif: k.1.clone(),
                                        }
                                        a {
                                            href: "",
                                            title: "Copy Public Key",
                                            class: "action_button",
                                            onclick: {
                                                let k_copy = k.clone();
                                                move |e| {
                                                    e.stop_propagation();
                                                    if let Ok(mut ctx) = ClipboardContext::new() {
                                                        if ctx.set_contents(k_copy.0.clone().into()).is_ok() {
                                                            *copied_to_clipboard.write() = CopiedToClipboard(Some(k_copy.0.clone()));
                                                        }
                                                    }
                                                }
                                            },
                                            Icon {
                                                width: 15,
                                                height: 15,
                                                fill: "black",
                                                icon: GoCopy,
                                            }
                                            if copied_to_clipboard.read().0 == Some(k.0.clone()) {
                                                Icon {
                                                    width: 15,
                                                    height: 15,
                                                    fill: "green",
                                                    icon: GoCheck,
                                                }
                                            }
                                        },
                                        DeleteButton {
                                            k: k.0.clone(),
                                            private: false,
                                        }
                                    }
                                }
                        }
                    }
                }
            }
        }
    }
}

fn PrivateSignerSelect() -> Element {
    let dbresult = use_context::<Signal<std::io::Result<Database>>>();
    let dbread = dbresult.read();
    let my_keys = match dbread.deref() {
        Ok(ref db) => db
            .visible_contents
            .my_public_keys
            .clone()
            .into_iter()
            .map(|k| (k.fingerprint(), k))
            .collect::<BTreeMap<_, _>>(),
        Err(ref e) => {
            return rsx! {
                "Error reading database: {e}"
            }
        }
    };
    let my_keys_clone = my_keys.clone();

    let mut selected_private_signer = use_context::<Signal<SelectedPrivateSigner>>();
    let mut sign_and_copy_status = use_context::<Signal<SignAndCopyStatus>>();
    let k = selected_private_signer.read().deref().0.clone();
    let selected_fingerprint = k.map(|k| k.fingerprint());

    rsx! {
        select {
            oninput: move |evt| {
                let mut selected_signer = selected_private_signer.write();
                let selected_private_signer = selected_signer.deref_mut();
                if let Some(k) = my_keys_clone.get(&evt.value()) {
                    *selected_private_signer = SelectedPrivateSigner(Some(k.clone()));
                    *sign_and_copy_status.write() = SignAndCopyStatus(false);
                }
            },
            for (fp, k) in my_keys {
                option {
                    value: "{fp}",
                    selected: {
                        selected_fingerprint.as_ref().map(|k| &fp == k).unwrap_or(false)
                    },
                    {
                        format!("{} <{}> {}", k.holder().name(), k.holder().email(), fp)
                    }
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Props)]
struct PublicSignerSelectProps {
    k: PublicKey,
}

fn PublicSignerSelect(props: PublicSignerSelectProps) -> Element {
    let mut selected_public_signers = use_context::<Signal<SelectedPublicSigners>>();
    let mut sign_and_copy_status = use_context::<Signal<SignAndCopyStatus>>();
    let current_signers = selected_public_signers.read();
    let k = props.k.clone();
    rsx! {
            input {
                oninput: move |e| {
                    let mut signers = selected_public_signers.write();
                    let signers = signers.deref_mut();
                    if e.value() == "true" {
                        signers.0.insert(props.k.clone().clone());
                    } else {
                        signers.0.remove(&props.k);
                    }
                    *sign_and_copy_status.write() = SignAndCopyStatus(false);
                },
                checked: current_signers.0.contains(&k),
                "type": "checkbox",
            }
    }
}

fn Sign() -> Element {
    let dbresult = use_context::<Signal<std::io::Result<Database>>>();
    let dbread = dbresult.read();
    let their_keys = match dbread.deref() {
        Ok(ref db) => db.visible_contents.their_public_keys.clone(),
        Err(ref e) => {
            return rsx! {
                "Error reading database: {e}"
            }
        }
    };

    let mut text_to_sign = use_context::<Signal<TextToSign>>();
    let text_to_sign_val = text_to_sign.read().deref().0.clone();
    let mut sign_and_copy_status = use_context::<Signal<SignAndCopyStatus>>();

    let filter = use_context::<Signal<SignerFilter>>();

    let filter_name = filter.read().0.name.to_lowercase();
    let filter_email = filter.read().0.email.to_lowercase();
    let filter_fingerprint = filter.read().0.fingerprint.replace(' ', "").to_lowercase();

    rsx! {
        div {
            class: "toolbar",
            Icon {
                class: "action_icon",
                width: 15,
                height: 15,
                fill: "black",
                icon: GoShieldLock,
            }
            SignAndCopy {}
        },
        div {
            class: "data",
        b {
            "Text To Sign: "
        }
        br {}
        textarea {
            value: "{text_to_sign_val}",
            oninput: move |evt| {
                *text_to_sign.write() = TextToSign(evt.value().clone());
                *sign_and_copy_status.write() = SignAndCopyStatus(false);
            },
            class: "sign_text"
        }
        br {}
        br {}
        b {
            "My Key: "
        }
        PrivateSignerSelect {}
        br {}
        br {}
        b {
            "Other Keys: "
        }
        br {}
        table {
            class: "otherkeys",
            thead {
                tr {
                    th {
                        "Name"
                    }
                    th {
                        "Email"
                    }
                    th {
                        "Fingerprint"
                    }
                    th {
                        "Verified?"
                    }
                    th {
                        "Include"
                    }
                }
            }
            tbody {
                FilterRow::<SignerFilter> {}
                for k in their_keys.into_iter() {
                    if k.0.holder().name().to_lowercase().contains(&filter_name)
                        && k.0.holder().email().to_lowercase().contains(&filter_email)
                        && k.0.fingerprint().replace(' ', "").to_lowercase().contains(&filter_fingerprint)
                    {
                            tr {
                                key: "{k.0.fingerprint()}",
                                td {
                                    class: "name",
                                    {k.0.holder().name()}
                                }
                                td {
                                    class: "email",
                                    {k.0.holder().email()}
                                }
                                td {
                                    class: "fingerprint",
                                    {k.0.fingerprint()}
                                }
                                td {
                                    class: "actions",
                                    if let Some(t) = k.1.verified_time() {
                                        span {
                                            title: "Verified {t.date()}",
                                            Icon {
                                                width: 15,
                                                height: 15,
                                                fill: "#00f",
                                                icon: GoVerified,
                                            }
                                        }
                                    }
                                }
                                td {
                                    class: "actions",
                                    PublicSignerSelect {
                                        k: k.0.clone()
                                    }
                                }
                            }
                    }
                }
            }
        }
        }
    }
}

fn SignAndCopy() -> Element {
    let mut dbresult = use_context::<Signal<std::io::Result<Database>>>();
    let text_to_sign = use_context::<Signal<TextToSign>>();
    let text_to_sign_val = text_to_sign.read().deref().0.clone();
    let selected_public_signers = use_context::<Signal<SelectedPublicSigners>>();
    let current_signers = selected_public_signers
        .read()
        .0
        .clone()
        .into_iter()
        .collect::<Vec<_>>();
    let selected_private_signer = use_context::<Signal<SelectedPrivateSigner>>();
    let mut sign_and_copy_status = use_context::<Signal<SignAndCopyStatus>>();
    let k = selected_private_signer.read().deref().0.clone();
    rsx! {
        button {
            onclick: move |_| {
                if let Ok(ref mut db) = dbresult.write().deref_mut() {
                    if let Ok(mut ctx) = ClipboardContext::new() {
                        if let Some(k) = &k {
                            if let Ok(signed_message) = db.sign(&text_to_sign_val, k, &current_signers) {
                                if ctx.set_contents(String::from(&signed_message)).is_ok() {
                                    *sign_and_copy_status.write() = SignAndCopyStatus(true);
                                }
                            }
                        }
                    }
                }
            },
            "Sign and Copy to Clipboard"
        }
        if sign_and_copy_status.read().0 {
            Icon {
                width: 15,
                height: 15,
                fill: "green",
                icon: GoCheck,
            }
        }
    }
}

fn PasteAndVerify() -> Element {
    let mut message_to_verify = use_context::<Signal<MessageToVerify>>();
    rsx! {
        button {
            onclick: move |_| {
                let mut message_to_verify = message_to_verify.write();
                let message = ClipboardContext::new()
                    .and_then(|mut ctx| ctx.get_contents())
                        .ok()
                        .map(|m| SignedMessage::from_str(&m));
                *message_to_verify = MessageToVerify(message);
            },
            "Verify Message From Clipboard"
        }
    }
}

#[derive(Clone, PartialEq, Props)]
struct VerificationResultsProps {
    signed_message: SignedMessage,
}

fn VerificationResults(props: VerificationResultsProps) -> Element {
    let dbresult = use_context::<Signal<std::io::Result<Database>>>();
    let (known_keys, my_keys) = match *dbresult.read() {
        Ok(ref db) => (
            db.visible_contents.their_public_keys.clone(),
            db.visible_contents.my_public_keys.clone(),
        ),
        Err(_) => (BTreeMap::new(), BTreeSet::new()),
    };

    let mut all_known = true;
    let mut all_verified = true;
    for pubkey in props.signed_message.ring() {
        if !my_keys.contains(pubkey) {
            match known_keys.get(pubkey) {
                None => {
                    all_known = false;
                    all_verified = false;
                }
                Some(v_info) => {
                    if !v_info.is_verified() {
                        all_verified = false;
                    }
                }
            }
        }
    }

    let signed_message = props.signed_message.message.clone();

    if props.signed_message.verify() {
        rsx! {
            b {
                "Message:"
            }
            br {}
            "{props.signed_message.message}"
            br {}
            br {}
            b {
                if all_known && all_verified {
                    "This message was signed by someone with the private key associated with one of these verified identities:"
                } else if all_known {
                    "This message was signed by someone with the private key associated with one of these identities (all known, but not all verified):"
                } else {
                    "This message was signed by someone with the private key associated with one of these identities, but not all of these are known identities"
                }
            }
            br {}
            br {}
            table {
                thead {
                    th {
                        "Name"
                    }
                    th {
                        "Email"
                    }
                    th {
                        "Fingerprint"
                    }
                    th {
                        "Known"
                    }
                }
                tbody {
                    for pubkey in props.signed_message.ring() {
                        tr {
                            key: "{pubkey.fingerprint()}",
                            td {
                                class: "name",
                                "{pubkey.holder().name()}"
                            }
                            td {
                                class: "email",
                                "{pubkey.holder().email()}"
                            }
                            td {
                                class: "fingerprint",
                                "{pubkey.fingerprint()}"
                            }
                            td {
                                class: "actions",
                                if my_keys.contains(pubkey) || known_keys.get(pubkey).map(|v| v.is_verified()).unwrap_or(false) {
                                        span {
                                            title: "Key is verified",
                                            Icon {
                                                width: 15,
                                                height: 15,
                                                fill: "#00f",
                                                icon: GoVerified,
                                            }
                                        }
                                } else if my_keys.contains(pubkey) || known_keys.contains_key(pubkey) {
                                        span {
                                            title: "Key is known but unverified",
                                            Icon {
                                                width: 15,
                                                height: 15,
                                                fill: "#d80",
                                                icon: GoVerified,
                                            }
                                        }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        rsx! {
            b {
                "Message:"
            }
            br {}
            {signed_message}
            br {}
            "Failed to verify."
        }
    }
}

fn Verify() -> Element {
    let message_to_verify = use_context::<Signal<MessageToVerify>>();
    let message_to_verify_val = message_to_verify.read().deref().0.clone();
    match message_to_verify_val {
        // the message parsed correctly
        Some(Ok(signed_message)) => rsx! {
            div {
                class: "toolbar",
                Icon {
                    class: "action_icon",
                    width: 15,
                    height: 15,
                    fill: "black",
                    icon: GoShieldCheck,
                }
                PasteAndVerify {}
            },
            div {
                class: "data",
                div {
                    VerificationResults {
                        signed_message: signed_message
                    }
                }
            }
        },
        // the message failed to parse correctly
        Some(Err(_)) => rsx! {
            div {
                class: "toolbar",
                Icon {
                    class: "action_icon",
                    width: 15,
                    height: 15,
                    fill: "black",
                    icon: GoShieldCheck,
                }
                PasteAndVerify {}
            },
            div {
                class: "data",
                "parse failed"
            }
        },
        // no message was provided
        None => rsx! {
            div {
                class: "toolbar",
                Icon {
                    class: "action_icon",
                    width: 15,
                    height: 15,
                    fill: "black",
                    icon: GoShieldCheck,
                }
                PasteAndVerify {}
            },
            div {
                class: "data",
            }
        }
    }
}
