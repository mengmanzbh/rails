# frozen_string_literal: true

module ActionController #:nodoc:
  module ContentSecurity
    extend ActiveSupport::Concern

    # TODO: Content-Security-Policy overview and DSL documentation
    class PolicyCollection #:nodoc:
      def initialize
        @policies = { application: Policy.new }
      end

      def build(&block)
        @policies.clear
        instance_exec(&block) if block_given?
      end

      def empty?
        @policies.empty?
      end

      def fetch(name)
        begin
          @policies.fetch(name)
        rescue KeyError
          raise ArgumentError, "Unknown content security policy: #{name.inspect}"
        end
      end

      def policy(name, using: nil)
        @policies[name] = clone_or_create_policy(using)
        yield @policies[name] if block_given?
      end

      def inspect
        "<#{self.class} policies: #{@policies.keys.inspect}>"
      end

      def to_s
        inspect
      end

      private

        def clone_or_create_policy(name)
          return Policy.new unless name

          begin
            @policies.fetch(name).clone
          rescue KeyError
            raise ArgumentError, "Unknown content security policy: #{name.inspect}"
          end
        end
    end

    class Policy #:nodoc:
      MAPPINGS = {
        self:           "'self'",
        unsafe_eval:    "'unsafe-eval'",
        unsafe_inline:  "'unsafe-inline'",
        none:           "'none'",
        http:           "http:",
        https:          "https:",
        data:           "data:",
        mediastream:    "mediastream:",
        blob:           "blob:",
        filesystem:     "filesystem:",
        report_sample:  "'report-sample'",
        strict_dynamic: "'strict-dynamic'"
      }.freeze

      DIRECTIVES = {
        base_uri:        "base-uri",
        child_src:       "child-src",
        connect_src:     "connect-src",
        default_src:     "default-src",
        font_src:        "font-src",
        form_action:     "form-action",
        frame_ancestors: "frame-ancestors",
        frame_src:       "frame-src",
        img_src:         "img-src",
        manifest_src:    "manifest-src",
        media_src:       "media-src",
        object_src:      "object-src",
        script_src:      "script-src",
        style_src:       "style-src",
        worker_src:      "worker-src"
      }.freeze

      private_constant :MAPPINGS, :DIRECTIVES

      attr_reader :report_only, :directives

      def initialize
        @report_only = false
        @directives  = {}
      end

      def initialize_copy(other)
        @report_only = other.report_only
        @directives = copy_directives(other.directives)
      end

      def empty?
        @directives.empty?
      end

      DIRECTIVES.each do |name, directive|
        define_method(name) do |*sources|
          if sources.first
            @directives[directive] = apply_mappings(sources)
          else
            @directives.delete(directive)
          end
        end
      end

      def block_all_mixed_content(enabled = true)
        if enabled
          @directives["block-all-mixed-content"] = true
        else
          @directives.delete("block-all-mixed-content")
        end
      end

      def plugin_types(*types)
        if types.first
          @directives["plugin-types"] = types
        else
          @directives.delete("plugin-types")
        end
      end

      def report_only!(uri:)
        @report_only = true
        @directives["report-uri"] = [uri]
      end

      def report_uri(uri)
        @directives["report-uri"] = [uri]
      end

      def require_sri_for(*types)
        if types.first
          @directives["require-sri-for"] = types
        else
          @directives.delete("require-sri-for")
        end
      end

      def sandbox(*values)
        if values.empty?
          @directives["sandbox"] = true
        elsif values.first
          @directives["sandbox"] = values
        else
          @directives.delete("sandbox")
        end
      end

      def upgrade_insecure_requests(enabled = true)
        if enabled
          @directives["upgrade-insecure-requests"] = true
        else
          @directives.delete("upgrade-insecure-requests")
        end
      end

      def header_name
        if @report_only
          "Content-Security-Policy-Report-Only"
        else
          "Content-Security-Policy"
        end
      end

      def header_value(context = nil)
        build_directives(context).compact.join("; ") + ";"
      end

      private
        def copy_directives(directives)
          {}.tap do |copy|
            directives.each do |directive, sources|
              copy[directive] = sources.map(&:dup)
            end
          end
        end

        def apply_mappings(sources)
          sources.map do |source|
            case source
            when Symbol
              apply_mapping(source)
            when String, Proc
              source
            else
              raise ArgumentError, "Invalid content security policy source: #{source.inspect}"
            end
          end
        end

        def apply_mapping(source)
          if MAPPINGS.key?(source)
            MAPPINGS.fetch(source)
          else
            raise ArgumentError, "Unknown content security policy source mapping: #{source.inspect}"
          end
        end

        def build_directives(context)
          @directives.map do |directive, sources|
            if sources.is_a?(Array)
              "#{directive} #{build_directive(sources, context).join(' ')}"
            elsif sources
              directive
            else
              nil
            end
          end
        end

        def build_directive(sources, context)
          sources.map { |source| resolve_source(source, context) }
        end

        def resolve_source(source, context)
          case source
          when String
            source
          when Symbol
            source.to_s
          when Proc
            if context.nil?
              raise RuntimeError, "Missing context for the dynamic content security policy source: #{source.inspect}"
            else
              context.instance_exec(&source)
            end
          else
            raise RuntimeError, "Unexpected content security policy source: #{source.inspect}"
          end
        end
    end

    included do
      config_accessor :content_security_policies
      self.content_security_policies = PolicyCollection.new

      config_accessor :default_protect_content
      self.default_protect_content = false

      attr_accessor :content_security_policy
    end

    module ClassMethods
      # TODO: Documentation for `protect_content`
      def protect_content(options = {}, &block)
        policy_name = options.delete(:policy)

        before_action(options) do
          if policy_name
            policy = content_security_policies.fetch(policy_name)
          end

          if block_given?
            if policy
              policy = policy.clone
            else
              policy = Policy.new
            end

            yield policy
          end

          unless policy
            raise RuntimeError, "Please specify a content security policy"
          end

          unless policy.empty?
            self.content_security_policy = policy
          end
        end

        after_action :set_content_security_policy, unless: :content_security_policy_present?
      end
    end

    private

      def set_content_security_policy
        if policy = content_security_policy
          response.set_header(policy.header_name, policy.header_value(self))
        end
      end

      def content_security_policy_present?
        has_csp_header? || has_csp_report_only_header?
      end

      def has_csp_header?
        response.has_header?("Content-Security-Policy")
      end

      def has_csp_report_only_header?
        response.has_header?("Content-Security-Policy-Report-Only")
      end
  end
end
