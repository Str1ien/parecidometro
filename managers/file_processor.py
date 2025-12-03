import magic
from docx import Document
import fitz  # PyMuPDF
import logging

logger = logging.getLogger(__name__)


class FileProcessor:
    """Procesa diferentes tipos de archivos y extrae contenido para TLSH"""
    
    def __init__(self, file_data, filename):
        self.file_data = file_data
        self.filename = filename
        self.file_type = self._detect_file_type()
        
    def _detect_file_type(self):
        """Detecta el tipo de archivo usando libmagic"""
        mime = magic.Magic(mime=True)
        detected_type = mime.from_buffer(self.file_data)
        logger.debug(f"File type detected for {self.filename}: {detected_type}")
        return detected_type
    
    def get_file_type(self):
        """Retorna el tipo MIME detectado"""
        return self.file_type
    
    def process(self):
        """
        Procesa el archivo según su tipo
        Returns:
            tuple: (success: bool, content: bytes | error_message: str)
        """
        logger.info(f"Processing file: {self.filename} (type: {self.file_type})")
        
        # PDF
        if 'pdf' in self.file_type:
            return self._process_pdf()
        
        # Word
        elif 'word' in self.file_type or 'officedocument' in self.file_type:
            return self._process_docx()
        
        # Ejecutables y otros archivos: retornar contenido raw
        elif 'x-executable' in self.file_type or 'x-dosexec' in self.file_type or \
             'x-sharedlib' in self.file_type or 'elf' in self.file_type.lower():
            return self._process_binary()
        
        # Cualquier otro tipo de archivo: contenido raw
        else:
            return self._process_generic()
    
    def _process_binary(self):
        """
        Procesa binarios ejecutables (PE/ELF) - retorna contenido raw
        Similar al comportamiento del script de ejemplo
        """
        size = len(self.file_data)
        logger.debug(f"Processing binary: {self.filename} ({size} bytes)")
        
        if size < 50:
            logger.warning(f"Binary file too small: {self.filename} ({size} bytes)")
            return False, "Binary file too small (min 50 bytes for TLSH)"
        
        logger.info(f"Binary processed successfully: {self.filename}")
        return True, self.file_data
    
    def _process_generic(self):
        """
        Procesa cualquier archivo genérico - retorna contenido raw
        """
        size = len(self.file_data)
        logger.debug(f"Processing generic file: {self.filename} ({size} bytes)")
        
        if size < 50:
            logger.warning(f"Generic file too small: {self.filename} ({size} bytes)")
            return False, f"File too small (min 50 bytes for TLSH, got {size})"
        
        logger.info(f"Generic file processed successfully: {self.filename}")
        return True, self.file_data
    
    def _process_pdf(self):
        """Extrae texto de PDF"""
        import io
        try:
            logger.debug(f"Extracting text from PDF: {self.filename}")
            doc = fitz.open(stream=self.file_data, filetype="pdf")
            text = ""
            page_count = len(doc)
            
            for page in doc:
                text += page.get_text()
            doc.close()
            
            text_length = len(text.strip())
            
            if not text or text_length < 1:
                logger.warning(f"PDF has no extractable text: {self.filename} ({page_count} pages)")
                return False, f"PDF has no extractable text ({page_count} pages scanned)"
            
            logger.info(f"PDF processed successfully: {self.filename} ({page_count} pages, {text_length} chars extracted)")
            return True, text.encode('utf-8')
            
        except Exception as e:
            logger.error(f"Error extracting PDF {self.filename}: {e}", exc_info=True)
            return False, f"PDF extraction failed: {str(e)} - file may be corrupted or password-protected"
    
    def _process_docx(self):
        """Extrae texto de Word DOCX"""
        import io
        try:
            logger.debug(f"Extracting text from DOCX: {self.filename}")
            doc = Document(io.BytesIO(self.file_data))
            text = '\n'.join([para.text for para in doc.paragraphs])
            
            text_length = len(text.strip())
            para_count = len(doc.paragraphs)
            
            if not text or text_length < 1:
                logger.warning(f"DOCX has no extractable text: {self.filename} ({para_count} paragraphs)")
                return False, f"DOCX has no extractable text ({para_count} paragraphs found but all empty)"
            
            logger.info(f"DOCX processed successfully: {self.filename} ({para_count} paragraphs, {text_length} chars extracted)")
            return True, text.encode('utf-8')
            
        except Exception as e:
            logger.error(f"Error extracting DOCX {self.filename}: {e}", exc_info=True)
            return False, f"DOCX extraction failed: {str(e)} - file may be corrupted or unsupported format"
