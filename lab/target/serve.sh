#!/bin/sh
# Fake internal services: banner responders on :80 (web) and :5432 (db).
socat TCP-LISTEN:80,fork,reuseaddr SYSTEM:'echo HTTP-OK' &
exec socat TCP-LISTEN:5432,fork,reuseaddr SYSTEM:'echo DB-OK'
