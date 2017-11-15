# frozen_string_literal: true

require "abstract_unit"

class ContentSecurityPolicyCollectionTest < ActiveSupport::TestCase
  def setup
    @policies = ActionController::ContentSecurity::PolicyCollection.new
  end

  def test_new_policy_collection_includes_empty_application_policy
    policy = @policies.fetch(:application)

    assert_instance_of ActionController::ContentSecurity::Policy, policy
    assert_empty policy
  end

  def test_build_clears_existing_policies
    @policies.build {}

    assert_empty @policies
  end

  def test_fetch_raises_an_argument_error_with_unknown_policy
    exception = assert_raises(ArgumentError) do
      @policies.fetch(:undefined)
    end

    assert_equal "Unknown content security policy: :undefined", exception.message
  end

  def test_policy_raise_an_argument_error_when_inheriting_from_unknown_policy
    exception = assert_raises(ArgumentError) do
      @policies.build do
        policy :inherited, using: :undefined do |p|
          p.default_src "https://www.example.com"
        end
      end
    end

    assert_equal "Unknown content security policy: :undefined", exception.message
  end

  def test_policy_yields_a_policy_instance
    yielded = nil

    @policies.build do
      policy :application do |p|
        yielded = p
      end
    end

    assert_instance_of ActionController::ContentSecurity::Policy, yielded
  end

  def test_policy_inherits_from_an_existing_policy
    @policies.build do
      policy :application do |p|
        p.default_src "https://www.example.com"
      end

      policy :inherited, using: :application do |p|
      end
    end

    application = @policies.fetch(:application)
    inherited   = @policies.fetch(:inherited)

    assert_not_equal application, inherited
    assert_equal application.directives, inherited.directives
  end
end

class ContentSecurityPolicyTest < ActiveSupport::TestCase
  def setup
    @policy = ActionController::ContentSecurity::Policy.new
  end

  def test_policy_empty
    assert_empty @policy
  end

  def test_header_name
    assert_equal "Content-Security-Policy", @policy.header_name

    @policy.report_only!(uri: "/violations")
    assert_equal "Content-Security-Policy-Report-Only", @policy.header_name
  end

  def test_header_value
    assert_equal ";", @policy.header_value

    @policy.script_src :self
    assert_equal "script-src 'self';", @policy.header_value

    @policy.report_only!(uri: "/violations")
    assert_equal "script-src 'self'; report-uri /violations;", @policy.header_value
  end

  def test_mappings
    @policy.script_src :data
    assert_equal "script-src data:;", @policy.header_value

    @policy.script_src :mediastream
    assert_equal "script-src mediastream:;", @policy.header_value

    @policy.script_src :blob
    assert_equal "script-src blob:;", @policy.header_value

    @policy.script_src :filesystem
    assert_equal "script-src filesystem:;", @policy.header_value

    @policy.script_src :self
    assert_equal "script-src 'self';", @policy.header_value

    @policy.script_src :unsafe_inline
    assert_equal "script-src 'unsafe-inline';", @policy.header_value

    @policy.script_src :unsafe_eval
    assert_equal "script-src 'unsafe-eval';", @policy.header_value

    @policy.script_src :none
    assert_equal "script-src 'none';", @policy.header_value

    @policy.script_src :strict_dynamic
    assert_equal "script-src 'strict-dynamic';", @policy.header_value

    @policy.script_src :none, :report_sample
    assert_equal "script-src 'none' 'report-sample';", @policy.header_value
  end

  def test_fetch_directives
    @policy.child_src :self
    assert_match %r{child-src 'self'}, @policy.header_value

    @policy.child_src false
    assert_no_match %r{child-src}, @policy.header_value

    @policy.connect_src :self
    assert_match %r{connect-src 'self'}, @policy.header_value

    @policy.connect_src false
    assert_no_match %r{connect-src}, @policy.header_value

    @policy.default_src :self
    assert_match %r{default-src 'self'}, @policy.header_value

    @policy.default_src false
    assert_no_match %r{default-src}, @policy.header_value

    @policy.font_src :self
    assert_match %r{font-src 'self'}, @policy.header_value

    @policy.font_src false
    assert_no_match %r{font-src}, @policy.header_value

    @policy.frame_src :self
    assert_match %r{frame-src 'self'}, @policy.header_value

    @policy.frame_src false
    assert_no_match %r{frame-src}, @policy.header_value

    @policy.img_src :self
    assert_match %r{img-src 'self'}, @policy.header_value

    @policy.img_src false
    assert_no_match %r{img-src}, @policy.header_value

    @policy.manifest_src :self
    assert_match %r{manifest-src 'self'}, @policy.header_value

    @policy.manifest_src false
    assert_no_match %r{manifest-src}, @policy.header_value

    @policy.media_src :self
    assert_match %r{media-src 'self'}, @policy.header_value

    @policy.media_src false
    assert_no_match %r{media-src}, @policy.header_value

    @policy.object_src :self
    assert_match %r{object-src 'self'}, @policy.header_value

    @policy.object_src false
    assert_no_match %r{object-src}, @policy.header_value

    @policy.script_src :self
    assert_match %r{script-src 'self'}, @policy.header_value

    @policy.script_src false
    assert_no_match %r{script-src}, @policy.header_value

    @policy.style_src :self
    assert_match %r{style-src 'self'}, @policy.header_value

    @policy.style_src false
    assert_no_match %r{style-src}, @policy.header_value

    @policy.worker_src :self
    assert_match %r{worker-src 'self'}, @policy.header_value

    @policy.worker_src false
    assert_no_match %r{worker-src}, @policy.header_value
  end

  def test_document_directives
    @policy.base_uri "https://example.com"
    assert_match %r{base-uri https://example\.com;}, @policy.header_value

    @policy.plugin_types "application/x-shockwave-flash"
    assert_match %r{plugin-types application/x-shockwave-flash;}, @policy.header_value

    @policy.sandbox
    assert_match %r{sandbox;}, @policy.header_value

    @policy.sandbox "allow-scripts", "allow-modals"
    assert_match %r{sandbox allow-scripts allow-modals;}, @policy.header_value

    @policy.sandbox false
    assert_no_match %r{sandbox}, @policy.header_value
  end

  def test_navigation_directives
    @policy.form_action :self
    assert_match %r{form-action 'self';}, @policy.header_value

    @policy.frame_ancestors :self
    assert_match %r{frame-ancestors 'self';}, @policy.header_value
  end

  def test_reporting_directives
    @policy.report_uri "/violations"
    assert_match %r{report-uri /violations;}, @policy.header_value
  end

  def test_other_directives
    @policy.block_all_mixed_content
    assert_match %r{block-all-mixed-content;}, @policy.header_value

    @policy.block_all_mixed_content false
    assert_no_match %r{block-all-mixed-content}, @policy.header_value

    @policy.require_sri_for :script, :style
    assert_match %r{require-sri-for script style;}, @policy.header_value

    @policy.require_sri_for "script", "style"
    assert_match %r{require-sri-for script style;}, @policy.header_value

    @policy.require_sri_for
    assert_no_match %r{require-sri-for}, @policy.header_value

    @policy.upgrade_insecure_requests
    assert_match %r{upgrade-insecure-requests;}, @policy.header_value

    @policy.upgrade_insecure_requests false
    assert_no_match %r{upgrade-insecure-requests}, @policy.header_value
  end

  def test_multiple_sources
    @policy.script_src :self, :https
    assert_equal "script-src 'self' https:;", @policy.header_value
  end

  def test_multiple_directives
    @policy.script_src :self, :https
    @policy.style_src :self, :https
    assert_equal "script-src 'self' https:; style-src 'self' https:;", @policy.header_value
  end

  def test_dynamic_directives
    request = Struct.new(:host).new("www.example.com")
    controller = Struct.new(:request).new(request)

    @policy.script_src -> { request.host }
    assert_equal "script-src www.example.com;", @policy.header_value(controller)
  end

  def test_mixed_static_and_dynamic_directives
    @policy.script_src :self, -> { "foo.com" }, "bar.com"
    assert_equal "script-src 'self' foo.com bar.com;", @policy.header_value(Object.new)
  end

  def test_report_only
    @policy.report_only!(uri: "/violations")
    assert_equal "report-uri /violations;", @policy.header_value
    assert_equal "Content-Security-Policy-Report-Only", @policy.header_name
  end

  def test_invalid_directive_source
    exception = assert_raises(ArgumentError) do
      @policy.script_src [:self]
    end

    assert_equal "Invalid content security policy source: [:self]", exception.message
  end

  def test_missing_context_for_dynamic_source
    @policy.script_src -> { request.host }

    exception = assert_raises(RuntimeError) do
      @policy.header_value
    end

    assert_match %r{\AMissing context for the dynamic content security policy source:}, exception.message
  end

  def test_raises_runtime_error_when_unexpected_source
    @policy.plugin_types [:flash]

    exception = assert_raises(RuntimeError) do
      @policy.header_value
    end

    assert_match %r{\AUnexpected content security policy source:}, exception.message
  end
end

class ContentSecurityControllerTest < ActionController::TestCase
  class ContentSecurityController < ActionController::Base
    protect_content policy: :application
    protect_content policy: :report_only, only: :report
    protect_content only: :undefined

    protect_content only: :inline do |p|
      p.default_src :self
    end

    protect_content only: :conditional, if: :condition? do |p|
      p.default_src "https://true.example.com"
    end

    protect_content only: :conditional, unless: :condition? do |p|
      p.default_src "https://false.example.com"
    end

    def index
      head :ok
    end

    def report
      head :ok
    end

    def inline
      head :ok
    end

    def undefined
      head :ok
    end

    def conditional
      head :ok
    end

    private

      def condition?
        params[:condition] == "true"
      end
  end

  tests ContentSecurityController

  def setup
    @controller.content_security_policies.build do
      policy :application do |p|
        p.default_src :self, :https
      end

      policy :report_only, using: :application do |p|
        p.report_only!(uri: "/violations")
      end
    end
  end

  def test_generates_content_security_policy_header
    get :index
    assert_policy "default-src 'self' https:;"
  end

  def test_generates_content_security_policy_report_only_header
    get :report
    assert_policy "default-src 'self' https:; report-uri /violations;", report_only: true
  end

  def test_generates_inline_content_security_policy
    get :inline
    assert_policy "default-src 'self';"
  end

  def test_generates_conditional_content_security_policy
    get :conditional, params: { condition: "true" }
    assert_policy "default-src https://true.example.com;"

    get :conditional, params: { condition: "false" }
    assert_policy "default-src https://false.example.com;"
  end

  def test_raises_runtime_error_when_policy_undefined
    exception = assert_raises(RuntimeError) do
      get :undefined
    end

    assert_equal "Please specify a content security policy", exception.message
  end

  private

    def assert_policy(expected, report_only: false)
      assert_response :success

      if report_only
        expected_header = "Content-Security-Policy-Report-Only"
        unexpected_header = "Content-Security-Policy"
      else
        expected_header = "Content-Security-Policy"
        unexpected_header = "Content-Security-Policy-Report-Only"
      end

      assert_nil response.headers[unexpected_header]
      assert_equal expected, response.headers[expected_header]
    end
end
