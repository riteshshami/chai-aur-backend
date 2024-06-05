import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadToCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return {accessToken, refreshToken}

  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  // get all data from frontend
  const { fullname, email, username, password } = req.body;

  // check all the data or validate it - not empty
  if (
    [fullname, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }
  // check if user already exist: username or email
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exist");
  }

  // check files availability such as avatar
  const avatarLocalPath = req.files?.avatar[0]?.path;
  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files?.coverImage[0]?.path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar is required");
  }

  // upload them at cloudinary
  const avatar = await uploadToCloudinary(avatarLocalPath);
  const coverImage = await uploadToCloudinary(coverImageLocalPath);

  // check avatar
  if (!avatar) {
    throw new ApiError(400, "Avatar is required here");
  }

  // create user object - create entry in db
  const user = await User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  // remove password and refresh token field from response
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  // check response of user creation
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // return response
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User Registered Successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
  // req.body => data
  const { email, username, password } = req.body;

  // username or email
  if (!username || !email) {
    throw new ApiError(400, "Username or Email is required.");
  }

  // find the user
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  // password match
  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid User Credentials");
  }

  // access and refresh token
  const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

  // send cookies
  const loggedInUser = await User.findById(user._id).select("-password, refreshToken")

  const options = {
    httpOnly: true,
    secure: true
  }

  return res
  .status(200)
  .cookie("accessToken", accessToken, options)
  .cookie("refreshToken", refreshToken, options)
  .json(
    new ApiResponse(200, {
        user: loggedInUser, accessToken, refreshToken
    },
    "User loggedIn successfully"
    )
  )
});

const logoutUser = asyncHandler(async(req, res) => {
    User.findByIdAndUpdate(req.user._id, {
        $set: {
            refreshToken: undefined
        }
    }, {new: true})

    const options = {
        httpOnly: true,
        secure: true
      }

    return res.status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User loggedout successfully"));
})

export { registerUser, loginUser, logoutUser };
