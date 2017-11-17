# frozen_string_literal: true

module ActionController #:nodoc:
  module ContentSecurityPolicy
    # TODO: Documentation
    extend ActiveSupport::Concern

    module ClassMethods
      def content_security_policy(options = {}, &block)
        before_action(options) do
          if block_given?
            policy = request.content_security_policy.clone
            yield policy
            request.content_security_policy = policy
          end
        end
      end

      def content_security_policy_report_only(*args)
        options = args.extract_options!
        flag = args.empty? ? true : args.first.present?

        before_action(options) do
          request.content_security_policy_report_only = flag
        end
      end
    end
  end
end
