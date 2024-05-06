let
  pkgs = import <nixpkgs> {};
in pkgs.mkShell {
  buildInputs = [
    pkgs.python3
    pkgs.python3.pkgs.requests
    pkgs.python3.pkgs.pandas
    pkgs.python3.pkgs.numpy
    pkgs.python3.pkgs.keras
    pkgs.python3.pkgs.scikit-learn
    pkgs.python3.pkgs.matplotlib
    pkgs.python3.pkgs.tensorflow
    pkgs.python3.pkgs.configparser
    pkgs.jq
    pkgs.zlib
    pkgs.zlib-ng
  ];
  shellHook = ''
    # Tells pip to put packages into $PIP_PREFIX instead of the usual locations.
    # See https://pip.pypa.io/en/stable/user_guide/#environment-variables.
    export PIP_PREFIX=$(pwd)/_build/pip_packages
    export PYTHONPATH="$PIP_PREFIX/${pkgs.python3.sitePackages}:$PYTHONPATH"
    export PATH="$PIP_PREFIX/bin:$PATH"
    unset SOURCE_DATE_EPOCH
  '';
}
