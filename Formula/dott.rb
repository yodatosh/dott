class Dott < Formula
  desc "Private domain search. No middlemen."
  homepage "https://github.com/yodatosh/dott"
  version "0.6.9"

  on_macos do
    on_arm do
      url "https://github.com/yodatosh/dott/releases/download/v0.6.9/dott-aarch64-apple-darwin.tar.gz"
      sha256 "3fe9d2b63a8d7b4457f391d69c0372ce26145f645fd5de0c8a0a187f9951bac8"
    end
    on_intel do
      url "https://github.com/yodatosh/dott/releases/download/v0.6.9/dott-x86_64-apple-darwin.tar.gz"
      sha256 "449d6f6b034b1b41badcc36fee924e9d7b0b994c8320fe1847d14fc01b1dd93e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/yodatosh/dott/releases/download/v0.6.9/dott-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "81381ce2396b3f3e5ce201cbc17889fdb63d7b0382339745529ec82cffa03bb6"
    end
    on_intel do
      url "https://github.com/yodatosh/dott/releases/download/v0.6.9/dott-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "52e056e03698486ddc0c21b23d91da5315b82123240d0db59ddd59c81720e5f8"
    end
  end

  def install
    bin.install "dott"
  end

  test do
    assert_match "dott", shell_output("#{bin}/dott --help")
  end
end
