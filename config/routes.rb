Rails.application.routes.draw do
  resources :agents do
    member do
      post :run
      post :handle_details_post
      put :leave_scenario
      post :reemit_events
      delete :remove_events
      delete :memory, action: :destroy_memory
    end

    collection do
      put :toggle_visibility
      post :propagate
      get :type_details
      get :event_descriptions
      post :validate
      post :complete
      delete :undefined, action: :destroy_undefined
    end

    resources :logs, :only => [:index] do
      collection do
        delete :clear
      end
    end

    resources :events, :only => [:index]

    scope module: :agents do
      resources :dry_runs, only: [:index, :create]
    end
  end

  scope module: :agents do
    resources :dry_runs, only: [:index, :create]
  end

  resource :diagram, :only => [:show]

  resources :events, :only => [:index, :show, :destroy] do
    member do
      post :reemit
    end
  end

  resources :scenarios do
    collection do
      resource :scenario_imports, :only => [:new, :create]
    end

    member do
      get :share
      get :export
      put :enable_or_disable_all_agents
    end

    resource :diagram, :only => [:show]
  end

  resources :user_credentials, :except => :show do
    collection do
      post :import
    end
  end

  resources :services, :only => [:index, :destroy] do
    member do
      post :toggle_availability
    end
  end

  resources :jobs, :only => [:index, :destroy] do
    member do
      put :run
    end
    collection do
      delete :destroy_failed
      delete :destroy_all
      post :retry_queued
    end
  end

  namespace :admin do
    resources :users, except: :show do
      member do
        put :deactivate
        put :activate
        get :switch_to_user
      end
      collection do
        get :switch_back
      end
    end
  end

  get "/worker_status" => "worker_status#show"

  # Error Monitoring System Routes
  resources :error_monitoring, :only => [:index] do
    collection do
      get :statistics
      get :trends
      get :circuit_breakers
      get :recovery
      get :health
      get :configuration
      post :configuration, action: :update_configuration
      get :export_report
      post :force_circuit_state
      post :reset_circuit_breaker
      post :enable_degradation
      post :restore_functionality
    end
  end

  # Performance Monitoring Dashboard Routes
  get "/performance_monitoring" => "performance_monitoring#dashboard"
  get "/performance_monitoring/dashboard" => "performance_monitoring#dashboard"  
  get "/performance_monitoring/metrics" => "performance_monitoring#metrics"
  get "/performance_monitoring/status" => "performance_monitoring#status"
  get "/performance_monitoring/alerts" => "performance_monitoring#alerts"
  get "/performance_monitoring/history" => "performance_monitoring#history"
  get "/performance_monitoring/recommendations" => "performance_monitoring#recommendations"
  get "/performance_monitoring/report" => "performance_monitoring#report"
  post "/performance_monitoring/run_tests" => "performance_monitoring#run_tests"

  match "/users/:user_id/web_requests/:agent_id/:secret" => "web_requests#handle_request", :as => :web_requests, :via => [:get, :post, :put, :delete]
  post  "/users/:user_id/webhooks/:agent_id/:secret" => "web_requests#handle_request" # legacy
  post  "/users/:user_id/update_location/:secret" => "web_requests#update_location" # legacy

  devise_for :users,
             controllers: {
               omniauth_callbacks: 'omniauth_callbacks',
               registrations: 'users/registrations'
             },
             sign_out_via: [:post, :delete]

  if Rails.env.development?
    mount LetterOpenerWeb::Engine, at: "/letter_opener"
  end

  get "/about" => "home#about"
  root :to => "home#index"
end
