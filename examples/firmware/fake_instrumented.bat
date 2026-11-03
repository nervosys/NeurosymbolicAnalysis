@echo off
> "%SDA_PROBE_OUT%" (
echo {"t":"cov","f":"src/main.c","l":34,"n":50}
echo {"t":"cov","f":"src/main.c","l":47,"n":12}
echo {"t":"fault","f":"src/main.c","l":47,"k":"leak","m":"32 bytes reachable at exit, allocated in process()"}
)
