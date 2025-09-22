{
  description = "rust flake build and dev shell";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }: {

        packages.x86_64-linux.default = with nixpkgs.legacyPackages.x86_64-linux; stdenv.mkDerivation {
            pname = "myapp";
            version = "1.0.0";

            src = ./.;

            buildInputs = [
            rustc
            cargo
            ];

            buildPhase =''
             cargo build --release
            '';

            installPhase = ''
                mkdir -p $out/bin
                cp target/release/myapp $out/bin
            '';
        };

        devShells.x86_64-linux.default = with  nixpkgs.legacyPackages.x86_64-linux; mkShell {
        buildInputs = [
            rustc
            cargo
            rustfmt
            clippy
        ];
        shellHook = ''
        echo "rust dev shell"
        echo "rust version: $(rustc --version)"
        '';
    };
    
  };
}
