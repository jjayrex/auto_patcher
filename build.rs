fn main() {
    let mut res = winres::WindowsResource::new();
    res.set("ProductName", "Example AutoPatcher");
    res.set("LegalCopyright", "JJayRex");
    res.set("FileVersion", "0.1.0");
    res.set("ProductVersion", "0.1.0");
    res.compile().unwrap();
}