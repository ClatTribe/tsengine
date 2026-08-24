#!/bin/sh
# toolset.sh — which assets' tooling this image build installs.
#
# Sourced by the gated layers in docker/sandbox/Dockerfile. It lives as a real file, copied into the
# build, rather than being printf'd into existence inside a RUN: escaping a shell function through
# printf inside a Dockerfile is how you get "Syntax error: \"(\" unexpected" three layers deep, which
# is exactly what happened when this was inlined.
#
# TS_TOOLSET is a comma-separated asset list, or `full` for everything (production parity).

# ts_want_any <asset-list> — true when the build wants ANY asset in a space-separated list.
#
# WHY A LIST. Tools do not belong to one asset. grype is dispatched by BOTH container and repository;
# httpx by api, domain, ip AND web; sqlmap by api as well as web. Each was gated on a single asset,
# so the slim image for the OTHER asset stubbed a tool its handler dispatches — a container image
# with no grype, three images with no httpx. The gating vocabulary has to be able to say "either",
# or the groups can only ever be wrong for multi-asset tools.
ts_want_any() {
  for _want in $1; do
    if ts_want "${_want}"; then return 0; fi
  done
  return 1
}

# ts_want <asset> — true when the build should install this asset's tooling.
ts_want() {
  case ",${TS_TOOLSET}," in
    *,full,*) return 0 ;;
    *,"$1",*) return 0 ;;
    *) return 1 ;;
  esac
}

# ts_stub <binary> — write a placeholder that fails loudly.
#
# The runtime stage COPYs every tool binary unconditionally and Docker cannot make a COPY
# conditional, so a skipped tool still needs something at that path. A stub that exits non-zero with
# a clear reason is the honest filler: a partial image reports the tool as unavailable rather than
# behaving as though it ran and found nothing — the same rule the product applies to its findings.
ts_stub() {
  mkdir -p /go/bin
  cat > "/go/bin/$1" <<STUB
#!/bin/sh
echo "$1 is not installed in this image (built with TOOLSET=${TS_TOOLSET}). Rebuild with TOOLSET=full, or add this asset to the list." >&2
exit 127
STUB
  chmod +x "/go/bin/$1"
}

# ts_install <asset> <binary> <module@version> — install when selected, stub when not.
#
# A failed install also stubs rather than failing the build: one unavailable tool degrades that
# tool's wrapper, and the image-coverage test is what catches a tool that should have been there.
# ts_install <asset-list> <binary> <module@version> — install when ANY listed asset is selected.
#
# The first argument is a SPACE-SEPARATED LIST (quote it): every asset whose handler dispatches this
# tool. A single word still works and means what it always did.
ts_install() {
  _asset="$1"
  _bin="$2"
  shift 2
  if ts_want_any "${_asset}"; then
    go install "$@" || ts_stub "${_bin}"
  else
    echo "skip ${_bin} (TOOLSET=${TS_TOOLSET})"
    ts_stub "${_bin}"
  fi
}
