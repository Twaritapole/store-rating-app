# store-rating-app
# Gemfile - Required gems
gem 'devise' # For authentication
gem 'pundit' # For role-based authorization
gem 'pg' # PostgreSQL database
gem 'bootstrap'

generate(:scaffold, "User name:string email:string password_digest:string address:string role:integer")
generate(:scaffold, "Store name:string email:string address:string owner_id:integer rating:float")
generate(:scaffold, "Rating user_id:integer store_id:integer value:integer")

# models/user.rb
class User < ApplicationRecord
  has_secure_password
  enum role: { admin: 0, normal_user: 1, store_owner: 2 }
  has_many :ratings
  has_many :stores, foreign_key: :owner_id, dependent: :destroy
  validates :name, length: { minimum: 20, maximum: 60 }
  validates :address, length: { maximum: 400 }
  validates :password, length: { in: 8..16 }, format: { with: /(?=.*[A-Z])(?=.*[^a-zA-Z\d])/, message: "must have 1 uppercase and 1 special character" }
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }
end

# models/store.rb
class Store < ApplicationRecord
  belongs_to :owner, class_name: 'User', foreign_key: 'owner_id'
  has_many :ratings, dependent: :destroy
  validates :name, :email, :address, presence: true
end

# models/rating.rb
class Rating < ApplicationRecord
  belongs_to :user
  belongs_to :store
  validates :value, inclusion: { in: 1..5 }
end

# controllers/admin_controller.rb
class AdminController < ApplicationController
  before_action :authenticate_user!
  before_action :authorize_admin
  
  def dashboard
    @total_users = User.count
    @total_stores = Store.count
    @total_ratings = Rating.count
  end

  private
  def authorize_admin
    redirect_to root_path, alert: "Not authorized" unless current_user.admin?
  end
end

# controllers/stores_controller.rb
class StoresController < ApplicationController
  before_action :authenticate_user!
  def index
    @stores = Store.includes(:ratings).all
  end
end

# controllers/ratings_controller.rb
class RatingsController < ApplicationController
  before_action :authenticate_user!
  
  def create
    @rating = current_user.ratings.new(rating_params)
    if @rating.save
      redirect_to stores_path, notice: "Rating submitted!"
    else
      redirect_to stores_path, alert: "Invalid rating"
    end
  end
  
  private
  def rating_params
    params.require(:rating).permit(:store_id, :value)
  end
end
