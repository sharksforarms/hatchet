
# hatchet WASM

This crate is used to test wasm compatibility.

**Note**: This is a work in progress

## Building/Running

```bash
wasm-pack build --target web
```

```bash
python3 -m http.server .
firefox http://localhost:8000/
```
