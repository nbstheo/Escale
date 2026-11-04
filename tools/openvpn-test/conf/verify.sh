#!/bin/sh
# auth-user-pass-verify via-file : $1 = fichier (ligne 1 user, ligne 2 mot de passe)
u=$(sed -n 1p "$1"); p=$(sed -n 2p "$1")
[ "$u" = test ] && [ "$p" = secret ] && exit 0
exit 1
