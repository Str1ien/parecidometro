# Test files
El fichero comprimido `test_files.7z` contiene diferentes binarios para probar el funcionamiento de Pareicdómetro. **No tiene contraseña**. Concretamente:
- 13 binarios (formato PE).
- 4 binarios (formato ELF).
- 6 ficheros PDF.
- 6 ficheros de texto.

**ATENCIÓN**: El fichero `test_files.7z` contiene muestras de malware real. Concretamente, 4 muestras de la familia [Mirai](https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai). Estos ficheeros están marcados como **MALWARE** en el nombre. Los autores de este repositorio no se hacen reponsables del uso indebido de estos ficheros.

Una vez descomprimido el fichero `test_files.7z`, el contenido del directorio actual debería ser similar a:
```
├── 20211216_OWASP-MSP_OWASP_Top_Ten_2021.pdf
├── 6027.json
├── 6033.json
├── 6109.json
├── 6682.json
├── 6708_report.json
├── 6767.json
├── BCryptEncrypt.exe
├── CopyFileEx.exe
├── CreateFile2.exe
├── CreateFile.exe
├── CryptEncrypt.exe
├── DeleteFile.exe
├── DeleteFileTransacted.exe
├── drylab.pdf
├── InternetConnect.exe
├── InternetOpenUrl.exe
├── invoicesample.pdf
├── MALWARE_46c184ed8a33a88dfb7ceb780cba7c139071c45b078a27ac873e47610bf71bfc.elf
├── MALWARE_5875c8fcb2c4ff7551c1c29ee86abb5ab558a47cd2899e30ca19cddf96ffd919.elf
├── MALWARE_9a598c801604aacb47b2cddd1ea34849174777eccafb43f0a713a61072c45aa5.elf
├── MALWARE_b9527cfbbc7c89fb1e378db72aa00cd078db99c581b45bf41da4f16bec32af73.elf
├── README.md
├── rfc9110.pdf
├── sample_pdf_modified.pdf
├── sample_pdf_original.pdf
├── SuspendThread.exe
├── test_files.7z
├── VirtualProtectEx.exe
├── WriteFile.exe
└── WriteFileEx.exe
```