defmodule Recurse.Providers.Impls.AwsKmsSecretsProvider.FinchHttpClientTest do
  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.AwsKmsSecretsProvider.FinchHttpClient

  describe "pool_for_url/2" do
    test "routes EC2 IMDS metadata URLs through the IMDS pool" do
      url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

      assert FinchHttpClient.pool_for_url(url, []) == :imds_pool
    end

    test "routes EC2 IMDSv2 token URLs through the IMDS pool" do
      url = "http://169.254.169.254/latest/api/token"

      assert FinchHttpClient.pool_for_url(url, []) == :imds_pool
    end

    test "routes ECS task-role metadata URLs through the IMDS pool" do
      url = "http://169.254.170.2/v2/credentials/abc"

      assert FinchHttpClient.pool_for_url(url, []) == :imds_pool
    end

    test "honors explicit IMDS pool override" do
      url = "http://169.254.169.254/latest/meta-data/"

      assert FinchHttpClient.pool_for_url(url, finch_imds_pool: :test_imds_pool) ==
               :test_imds_pool
    end

    test "routes AWS service API URLs through the configured KMS pool" do
      url = "https://kms.us-west-2.amazonaws.com/"

      assert FinchHttpClient.pool_for_url(url, finch_pool: :custom_kms_pool) == :custom_kms_pool
    end

    test "uses the default KMS pool for non-metadata URLs" do
      url = "https://kms.us-west-2.amazonaws.com/"

      assert FinchHttpClient.pool_for_url(url, []) == :kms_pool
    end
  end
end
