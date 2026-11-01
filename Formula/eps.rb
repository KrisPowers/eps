# Homebrew formula for EPS, installed as the command `@`.
#
# This repo doubles as its own tap:
#
#   brew tap krispowers/eps https://github.com/KrisPowers/eps
#   brew install krispowers/eps/eps
#
# On each release, set `version` and the four `sha256` values from the
# release's .sha256 files.
class Eps < Formula
  desc "Read-only recon CLI: reports exposed ports and endpoint posture"
  homepage "https://github.com/KrisPowers/eps"
  version "1.0.0"
  license "Apache-2.0"

  base = "https://github.com/KrisPowers/eps/releases/download/v#{version}"

  on_macos do
    on_arm do
      url "#{base}/eps-aarch64-apple-darwin.tar.gz"
      sha256 "21864a931f54fe30d4f0d04c839350855be8231d86cfbd6842167176b89fae2b"
    end
    on_intel do
      url "#{base}/eps-x86_64-apple-darwin.tar.gz"
      sha256 "cac665f32df2f7883bf42789e32b62e7b1666fb9e191538868816f1ca7f15c36"
    end
  end

  on_linux do
    on_arm do
      url "#{base}/eps-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "4594a11178f3fb369e7455050a42c4b7deeee0fd1389718084a98f69b9ec73d5"
    end
    on_intel do
      url "#{base}/eps-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "817ca8a84f25a8be244e3a946ed6ded601a213f84334baaca76a1757848af153"
    end
  end

  def install
    # The archive ships the binary as `eps`; install it as `@`.
    bin.install "eps" => "@"
  end

  test do
    assert_match "recon", shell_output("#{bin}/@ --help")
  end
end
