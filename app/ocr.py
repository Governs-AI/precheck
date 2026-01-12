import base64
import io
import pytesseract
from PIL import Image, UnidentifiedImageError
from typing import Optional

def extract_text_from_image(base64_string: str) -> str:
    """
    Extracts text from a base64 encoded image string using Tesseract OCR.
    
    Args:
        base64_string: Base64 encoded image data (with or without data URI prefix)
        
    Returns:
        Extracted text or empty string if extraction fails
    """
    if not base64_string:
        return ""
        
    try:
        # Strip data URI prefix if present (e.g., "data:image/png;base64,...")
        if "," in base64_string:
            base64_string = base64_string.split(",")[1]
            
        # Decode base64
        image_data = base64.b64decode(base64_string)
        
        # Open image with PIL
        image = Image.open(io.BytesIO(image_data))
        
        # Run OCR
        text = pytesseract.image_to_string(image)
        
        return text.strip()
        
    except (UnidentifiedImageError, ValueError, base64.binascii.Error) as e:
        print(f"Error processing image for OCR: {e}")
        return ""
    except Exception as e:
        print(f"Unexpected error in OCR: {e}")
        return ""
