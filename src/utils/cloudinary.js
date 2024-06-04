import {v2 as cloudinary} from 'cloudinary';
import fs from "fs";
import dotenv from "dotenv";

dotenv.config({
    path: './.env'
})

cloudinary.config({ 
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
    api_key: process.env.CLOUDINARY_API_KEY, 
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const uploadToCloudinary = async (localFilePath) => {
    try{
        if (!localFilePath) return null
        // upload the file on cloudinary
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        fs.unlinkSync(localFilePath)
        return response;
    }catch(error){
        fs.unlinkSync(localFilePath) //remove the saved temporary file as the upload operation failed.
        return null;
    }
}

export {uploadToCloudinary};