{
  description = "go dev shell";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }: {


    packages.x86_64-linux.myapp = with nixpkgs.legacyPackages.x86_64-linux; stdenv.mkDerivation {
        pname = "myapp";
        version = "1.0.0";

        src = ./.;

        buildInputs = [
            go
        ];

        buildPhase = ''
            export GOCACHE=$PWD/.gocache
            go build -o myapp main.go
        '';

        installPhase = ''
            mkdir -p $out/bin
            cp myapp $out/bin/
        '';
    };

     
    devShells.x86_64-linux.go = with nixpkgs.legacyPackages.x86_64-linux; mkShell {
        buildInputs = [
        go
        ];
        shellHook = ''
        echo "go dev shell"
        '';
    };
  };
}
