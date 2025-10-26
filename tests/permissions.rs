mod common;

use bc_envelope::prelude::*;
use bc_xid::*;
use indoc::indoc;

#[test]
fn permissions() {
    let mut permissions = Permissions::new();
    assert!(permissions.allow().is_empty());
    assert!(permissions.deny().is_empty());

    permissions.allow_mut().insert(Privilege::All);
    permissions.deny_mut().insert(Privilege::Verify);

    let envelope = permissions.add_to_envelope(Envelope::new("Subject"));
    let permissions2 = Permissions::try_from_envelope(&envelope).unwrap();
    assert_eq!(permissions, permissions2);

    #[rustfmt::skip]
    assert_actual_expected!(envelope.format(), indoc! {r#"
        "Subject" [
            'allow': 'All'
            'deny': 'Verify'
        ]
    "#}.trim());
}
