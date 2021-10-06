# Build and setup autocert

## Build bootstrapper image

Inside directory `./bootstrapper/`

For local KIND cluster test:

```bash
docker build -t cr.step.sm/smallstep/autocert-bootstrapper:0.14.0 . && kind load docker-image cr.step.sm/smallstep/autocert-bootstrapper:0.14.0
```

For formal build:

```bash
docker build -t truvetadevacr.azurecr.io/autocert-bootstrapper:1.4 .
```

## Build renewer image

Inside directory `./renewer/`

For formal build:

```bash
docker build -t truvetadevacr.azurecr.io/autocert-renewer:1.1 .
```

## Build controller image

For local KIND cluster test:

```bash
docker build . -t cr.step.sm/smallstep/autocert-controller:0.14.0 && kind load docker-image cr.step.sm/smallstep/autocert-controller:0.14.0
```

For formal build:

```bash
docker build -t truvetadevacr.azurecr.io/autocert-controller:1.6 .
```
