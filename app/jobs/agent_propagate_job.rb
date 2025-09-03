# frozen_string_literal: true

class AgentPropagateJob < ActiveJob::Base

  queue_as :propagation

  def perform
    Agent.receive!
  end

  def self.can_enqueue?
    case queue_adapter.class.name # not using class since it would load adapter dependent gems
    when 'ActiveJob::QueueAdapters::DelayedJobAdapter'
      Delayed::Job.where(failed_at: nil, queue: 'propagation').count.zero?
    when 'ActiveJob::QueueAdapters::ResqueAdapter'
      Resque.size('propagation').zero? &&
             Resque.workers.count { |w| w.job && w.job['queue'] && w.job['queue']['propagation'] }.zero?
    else
      raise NotImplementedError, "unsupported adapter: #{queue_adapter}"
    end
  end

end
