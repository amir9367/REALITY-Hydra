//! The ±1 epoch acceptance window (REALITY.md §5.4, §13): a client whose clock
//! is up to one epoch off still presents an SNI the server accepts.

use pool_engine::{MasterList, PoolEntry, accepted_pool_window, keyed_epoch_subset};

const SECRET: &[u8] = b"epoch window test secret";
const SALT: [u8; 16] = *b"abcdefabcdefabcd";

fn master() -> MasterList {
    // Large enough that the ±1 window union stays well below the full list.
    let entries = (0..40)
        .map(|i| PoolEntry::new(format!("d{i:02}.cdn.example"), 1.0 + (i % 7) as f64))
        .collect();
    MasterList::new(entries).unwrap()
}

#[test]
fn window_is_superset_of_current_epoch() {
    let m = master();
    let e = 500;
    let active = keyed_epoch_subset(SECRET, &SALT, &m, e, 5);
    let win = accepted_pool_window(SECRET, &SALT, &m, e, 5);
    for sni in active.snis() {
        assert!(win.contains(sni), "window missing current-epoch SNI {sni}");
    }
    assert!(win.len() >= active.len());
}

#[test]
fn client_one_epoch_off_is_accepted() {
    let m = master();
    let server_epoch = 500;
    for client_epoch in [server_epoch - 1, server_epoch, server_epoch + 1] {
        let client = keyed_epoch_subset(SECRET, &SALT, &m, client_epoch, 5);
        let win = accepted_pool_window(SECRET, &SALT, &m, server_epoch, 5);
        for sni in client.snis() {
            assert!(
                win.contains(sni),
                "server at epoch {server_epoch} rejected SNI {sni} from client at {client_epoch}"
            );
        }
    }
}

#[test]
fn window_is_bounded_not_unlimited() {
    // Sanity: the window is ±1, not infinite. A client two epochs ahead should
    // present at least one SNI outside the server's accepted set.
    let m = master();
    let server_epoch = 500;
    let client = keyed_epoch_subset(SECRET, &SALT, &m, server_epoch + 2, 5);
    let win = accepted_pool_window(SECRET, &SALT, &m, server_epoch, 5);
    let all_inside = client.snis().all(|s| win.contains(s));
    assert!(
        !all_inside,
        "client two epochs off was fully inside the ±1 window"
    );
}
