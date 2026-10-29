# Homebrew formula for portscan, installed as the command `@`.
#
# This repo doubles as its own tap:
#
#   brew tap krispowers/portscan https://github.com/KrisPowers/portscan
#   brew install krispowers/portscan/portscan
#
# When you cut a release, fill in `version` and the four `sha256` values (the
# release workflow prints them).
class Portscan < Formula
  desc "Read-only recon CLI: reports exposed ports and endpoint posture"
  homepage "https://github.com/KrisPowers/portscan"
  version "0.1.0"
  license "Apache-2.0"

  base = "https://github.com/KrisPowers/portscan/releases/download/v#{version}"

  on_macos do
    on_arm do
      url "#{base}/portscan-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "#{base}/portscan-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "#{base}/portscan-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "#{base}/portscan-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    # The archive ships the binary as `portscan`; install it as `@`.
    bin.install "portscan" => "@"
  end

  test do
    assert_match "recon", shell_output("#{bin}/@ --help")
  end
end
