# This formula is auto-updated by the release CI.
# To use: brew tap vral-parmar/tap && brew install acdi
class Acdi < Formula
  desc "Automated Cryptography Discovery & Inventory for PQC migration"
  homepage "https://github.com/vral-parmar/acdi"
  version "0.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/vral-parmar/acdi/releases/download/v#{version}/acdi-aarch64-apple-darwin"
      sha256 "PLACEHOLDER_MACOS_ARM64"
    else
      url "https://github.com/vral-parmar/acdi/releases/download/v#{version}/acdi-x86_64-apple-darwin"
      sha256 "PLACEHOLDER_MACOS_X86_64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/vral-parmar/acdi/releases/download/v#{version}/acdi-aarch64-unknown-linux-musl"
      sha256 "PLACEHOLDER_LINUX_ARM64"
    else
      url "https://github.com/vral-parmar/acdi/releases/download/v#{version}/acdi-x86_64-unknown-linux-musl"
      sha256 "PLACEHOLDER_LINUX_X86_64"
    end
  end

  def install
    # The downloaded resource is the raw binary — rename it to 'acdi'
    bin.install Dir["acdi-*"].first => "acdi"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/acdi --version")
  end
end
