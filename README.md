# ECNU Portal Helper 

Login ECNU portal in console

## Usage

### Login

``` sh
./ecnu_portal.py login username password
# Login...
# Login ok
```

### Logout


``` sh
./ecnu_portal.py logout
# Logout...
# Logout success
```

### Status

``` sh
./ecnu_portal.py status
# ('219.228.147.180', '51215903067')
```

### NetworkManager Dispatcher

1. Copy `ecnu_portal.py` to `/etc/NetworkManager/dispatcher.d/90-ecnu-portal.py`
2. Replace `__INTERFACE__`, `__USERNAME__` and  `__PASSWORD__` around the last 3 lines

<!--
  vi: ft=markdown
-->
