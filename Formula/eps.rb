# Homebrew formula for EPS, installed as the command `@`.
#
# This repo doubles as its own tap:
#
#   brew tap krispowers/eps https://github.com/KrisPowers/eps
#   brew install krispowers/eps/eps
#
# When you cut a release, fill in `version` and the four `sha256` values (the
# release workflow prints them).
class Eps < Formula
  desc "Read-only recon CLI: reports exposed ports and endpoint posture"
  homepage "https://github.com/KrisPowers/eps"
  version "1.0.0"
  license "Apache-2.0"

  base = "https://github.com/KrisPowers/eps/releases/download/v#{version}"

  on_macos do
    on_arm do
      url "#{base}/eps-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "#{base}/eps-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "#{base}/eps-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "#{base}/eps-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
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
