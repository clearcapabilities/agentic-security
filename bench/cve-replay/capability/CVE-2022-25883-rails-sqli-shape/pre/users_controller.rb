class UsersController < ApplicationController
  def index
    name = params[:name]
    @users = User.where("name = '#{name}'")
    render json: @users
  end
end
