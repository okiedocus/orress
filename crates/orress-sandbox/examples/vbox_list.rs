fn main() {
    println!("available: {}", orress_sandbox::vbox::available());
    match orress_sandbox::vbox::list_vms() {
        Ok(vms) => {
            for vm in &vms {
                let st = orress_sandbox::vbox::state(&vm.name).unwrap_or_else(|e| e);
                let snaps = orress_sandbox::vbox::snapshots(&vm.name).unwrap_or_default();
                println!("{} state={st} snapshots={snaps:?}", vm.name);
            }
        }
        Err(e) => println!("error: {e}"),
    }
}
