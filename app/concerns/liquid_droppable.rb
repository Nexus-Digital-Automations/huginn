# frozen_string_literal: true

module LiquidDroppable

  class Drop < Liquid::Drop

    def initialize(object)
      @object = object
    end

    def to_s
      @object.to_s
    end

    def each
      (public_instance_methods - Drop.public_instance_methods).each do |name|
        yield [name, __send__(name)]
      end
    end

    def as_json
      return {} unless defined?(self.class::METHODS)

      self.class::METHODS.to_h { |m| [m, send(m).as_json] }
    end

  end

  class MatchDataDrop < Drop

    METHODS = %w[pre_match post_match names size].freeze

    METHODS.each do |attr|
      define_method(attr) do
        @object.__send__(attr)
      end
    end

    def to_s
      @object[0]
    end

    def liquid_method_missing(method)
      @object[method]
    rescue IndexError
      nil
    end

  end

  class ::MatchData

    def to_liquid
      MatchDataDrop.new(self)
    end

  end

  require 'uri'

  class URIDrop < Drop

    METHODS = URI::Generic::COMPONENT

    METHODS.each do |attr|
      define_method(attr) do
        @object.__send__(attr)
      end
    end

  end

  class ::URI::Generic

    def to_liquid
      URIDrop.new(self)
    end

  end

  class ActiveRecordCollectionDrop < Drop

    include Enumerable

    def each(&)
      @object.each(&)
    end

    # required for variable indexing as array
    def [](i)
      case i
      when Integer
        @object[i]
      when 'size', 'first', 'last'
        __send__(i)
      end
    end

    # required for variable indexing as array
    def fetch(i, &)
      @object.fetch(i, &)
    end

    # compatibility with array; also required by the `size` filter
    def size
      @object.count
    end

    # compatibility with array
    def first
      @object.first
    end

    # compatibility with array
    def last
      @object.last
    end

    # This drop currently does not support the `slice` filter.

  end

  class ::ActiveRecord::Associations::CollectionProxy

    def to_liquid
      ActiveRecordCollectionDrop.new(self)
    end

  end

end
