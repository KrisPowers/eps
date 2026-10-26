# Homebrew formula for `at`, installed as the command `@`.
#
# This repo doubles as its own tap, so users can:
#
#   brew tap krispowers/at https://github.com/krispowers/at
#   brew install krispowers/at/at
#
# NOTE: the project repo is currently private. Until the first public release,
# the release archives referenced below will not exist and the formula will not
# install. When you cut a release, fill in `version` and the four `sha256`
# values (the release workflow prints them), and the formula is live.
#
# The single host to change is the `base` url below.
class At < Formula
  desc "Read-only recon CLI: reports exposed ports and endpoint posture"
  homepage "https://at.krispowers.dev"
  version "0.1.0"
  license "Apache-2.0"

  base = "https://at.krispowers.dev/releases/v#{version}"

  on_macos do
    on_arm do
      url "#{base}/at-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "#{base}/at-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "#{base}/at-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "#{base}/at-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    # The archive ships the binary as `at`; install it as `@`.
    bin.install "at" => "@"
  end

  test do
    assert_match "recon", shell_output("#{bin}/@ --help")
  end
end
