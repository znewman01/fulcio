{
  inputs = {
    nixpkgs.url = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system: {
      devShells.default = let pkgs = nixpkgs.legacyPackages.${system};
      in pkgs.mkShell {
        buildInputs = with pkgs; [
          nixfmt
          jq
          cosign
          docker-compose
          protobuf3_12
          go
          gnumake
          gocode
          gore
          gomodifytags
          gopls
          go-symbols
          gopkgs
          go-outline
          gotests
          gotools
          golangci-lint
          grpcurl
        ];
        COSIGN_EXPERIMENTAL = 1;
      };
    });
}
