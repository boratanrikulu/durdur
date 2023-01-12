# Durdur

[Durdur](https://www.youtube.com/watch?v=sF0QweCoaMo) is a CLI tool for Linux implementing L3/L4 packet dropping with eBPF/Go (proof of concept).

## How to install

### From source;

Build and use `build/durdur` binary.

```
make build
```

## How to use

Run all commands via **root privileges**.  

1. Attach the program to BPFFS.
```sh
durdur attach --interface wlp3s0
```

2. Add rules. You can use `to`, `from` or `dns` params.
```sh
durdur drop --from "192.0.1.1"
```

3. Remove rules.
```sh
durdur undrop --from "192.0.1.1"
```

4. Detach the program from BPFFS. (Cleans all resources)
```sh
durdur detach
```

https://user-images.githubusercontent.com/20258973/195852545-0f7578ad-4417-453d-8d64-64a237eca640.mp4

## Copyright

[GPL-3.0 license](https://github.com/boratanrikulu/durdur/blob/main/LICENSE),  
Copyright 2022 Bora Tanrikulu <[me@bora.sh](mailto:me@bora.sh)>

## TODO

- [ ] Add DNS support.
