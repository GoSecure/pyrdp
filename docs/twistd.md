# Using PyRDP with twistd

The PyRDP MITM component was also implemented as a twistd plugin. This enables
you to run it in debug mode and allows you to get an interactive debugging repl
(pdb) if you send a `SIGUSR2` to the twistd process.

```
twistd --debug pyrdp -t <target>
```

Then to get the repl:

```
killall -SIGUSR2 twistd
```

# Using PyRDP with twistd in Docker

In a directory with our `docker-compose.yml` you can run something like this:

```
docker-compose run -p 3389:3389 pyrdp twistd --debug pyrdp --target 192.168.1.10:3389
```

This will allocate a TTY and you will have access to `Pdb`'s REPL. Trying to add `--debug` to the `docker-compose.yml` command will fail because there is no TTY allocated.
