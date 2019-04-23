Imports System.IO                       'Importing the FileManager
Imports System.Security.Cryptography    'Importing the System Security Cryptography Service

Public Module EncryptionRD


    '+==================================================+
    '|            Setup : Global Variables              |
    '+==================================================+

    Dim fsInput As System.IO.FileStream
    Dim fsOutput As System.IO.FileStream


    Public Enum CryptoAction
        ActionEncrypt = 1
        ActionDecrypt = 2
    End Enum

    Public Function EncryptDecryptFile(ByVal SelectedFileLocation As String, ByVal OutputFileLocation As String, ByVal EncryptionPassword As String, ByVal Direction As CryptoAction)

        '+==================================================+
        '|          Step (1) : Create the Key               |
        '+==================================================+

        'Convert strPassword to an array and store in chrData.
        Dim KEY_chrData() As Char = EncryptionPassword.ToCharArray
        'Use intLength to get strPassword size.
        Dim KEY_intLength As Integer = KEY_chrData.GetUpperBound(0)
        'Declare bytDataToHash and make it the same size as chrData.
        Dim KEY_bytDataToHash(KEY_intLength) As Byte

        'Use For Next to convert and store chrData into bytDataToHash.
        For i As Integer = 0 To KEY_chrData.GetUpperBound(0)
            KEY_bytDataToHash(i) = CByte(Asc(KEY_chrData(i)))
        Next

        'Declare what hash to use.
        Dim KEY_SHA512 As New SHA512Managed
        'Declare bytResult, Hash bytDataToHash and store it in bytResult.
        Dim KEY_bytResult As Byte() = KEY_SHA512.ComputeHash(KEY_bytDataToHash)
        'Declare bytKey(31).  It will hold 256 bits.
        Dim bytKey(31) As Byte

        'Use For Next to put a specific size (256 bits) of 
        'bytResult into bytKey. The 0 To 31 will put the first 256 bits
        'of 512 bits into bytKey.
        For i As Integer = 0 To 31
            bytKey(i) = KEY_bytResult(i)
        Next



        'Define the CreatedKey from the Password Submitted
        Dim CreatedKey As Byte() = bytKey



        '+==================================================+
        '|          Step (2) : Create the IV                |
        '+==================================================+

        'Convert strPassword to an array and store in chrData.
        Dim IV_chrData() As Char = EncryptionPassword.ToCharArray
        'Use intLength to get strPassword size.
        Dim IV_intLength As Integer = IV_chrData.GetUpperBound(0)
        'Declare bytDataToHash and make it the same size as chrData.
        Dim IV_bytDataToHash(IV_intLength) As Byte

        'Use For Next to convert and store chrData into bytDataToHash.
        For i As Integer = 0 To IV_chrData.GetUpperBound(0)
            IV_bytDataToHash(i) = CByte(Asc(IV_chrData(i)))
        Next

        'Declare what hash to use.
        Dim IV_SHA512 As New System.Security.Cryptography.SHA512Managed
        'Declare bytResult, Hash bytDataToHash and store it in bytResult.
        Dim IV_bytResult As Byte() = IV_SHA512.ComputeHash(IV_bytDataToHash)
        'Declare bytIV(15).  It will hold 128 bits.
        Dim bytIV(15) As Byte

        'Use For Next to put a specific size (128 bits) of 
        'bytResult into bytIV. The 0 To 30 for bytKey used the first 256 bits.
        'of the hashed password. The 32 To 47 will put the next 128 bits into bytIV.
        For i As Integer = 32 To 47
            bytIV(i - 32) = IV_bytResult(i)
        Next




        'Define the CreatedIV from the Password Submitted
        Dim CreatedIV As Byte() = bytIV


        '+==================================================+
        '|          Step (3) : Encrypt the Files            |
        '+==================================================+


        Dim edsOutput As String 'Function Output for EncryptorDecryptorService


        Try 'In case of errors.

            'Setup file streams to handle input and output.
            fsInput = New System.IO.FileStream(SelectedFileLocation, FileMode.Open, FileAccess.Read)
            fsOutput = New System.IO.FileStream(OutputFileLocation, FileMode.OpenOrCreate, FileAccess.Write)

            fsOutput.SetLength(0) 'make sure fsOutput is empty

            'Declare variables for encrypt/decrypt process.
            Dim bytBuffer(4096) As Byte 'holds a block of bytes for processing
            Dim lngBytesProcessed As Long = 0 'running count of bytes processed
            Dim lngFileLength As Long = fsInput.Length 'the input file's length
            Dim intBytesInCurrentBlock As Integer 'current bytes being processed
            Dim csCryptoStream As CryptoStream

            'Declare your CryptoServiceProvider.
            Dim cspRijndael As New System.Security.Cryptography.RijndaelManaged

            'Determine if ecryption or decryption and setup CryptoStream.
            Select Case Direction
                Case CryptoAction.ActionEncrypt
                    csCryptoStream = New CryptoStream(fsOutput,
                cspRijndael.CreateEncryptor(CreatedKey, CreatedIV),
                CryptoStreamMode.Write)

                Case CryptoAction.ActionDecrypt
                    csCryptoStream = New CryptoStream(fsOutput,
                cspRijndael.CreateDecryptor(CreatedKey, CreatedIV),
                CryptoStreamMode.Write)
            End Select

            'Use While to loop until all of the file is processed.
            While lngBytesProcessed < lngFileLength
                'Read file with the input filestream.
                intBytesInCurrentBlock = fsInput.Read(bytBuffer, 0, 4096)
                'Write output file with the cryptostream.
                csCryptoStream.Write(bytBuffer, 0, intBytesInCurrentBlock)
                'Update lngBytesProcessed
                lngBytesProcessed = lngBytesProcessed + CLng(intBytesInCurrentBlock)
            End While

            'Close FileStreams and CryptoStream.
            csCryptoStream.Close()
            fsInput.Close()
            fsOutput.Close()

            'If encrypting then delete the original unencrypted file.
            If Direction = CryptoAction.ActionEncrypt Then
                Dim fileOriginal As New FileInfo(SelectedFileLocation)
                fileOriginal.Delete()
            End If

            'If decrypting then delete the encrypted file.
            If Direction = CryptoAction.ActionDecrypt Then
                Dim fileEncrypted As New FileInfo(SelectedFileLocation)
                fileEncrypted.Delete()
            End If

            'Update the user when the file is done.
            If Direction = CryptoAction.ActionEncrypt Then
                edsOutput = "{""status"":""01"",""information:"":""Encryption Complete"",""data"":{""totalBytes"":"" " & lngBytesProcessed.ToString() & " "",""inputFile"":""" & SelectedFileLocation.ToString & """,""outputFile"":""" & OutputFileLocation.ToString & """,""key"":""" & bytKey.ToString() & """,""IV"":""" & bytIV.ToString() & """}}"
            Else
                edsOutput = "{""status"":""00"",""information:"":""Decryption Complete"",""data"":{""totalBytes"":"" " & lngBytesProcessed.ToString() & " "",""inputFile"":""" & SelectedFileLocation.ToString & """,""outputFile"":""" & OutputFileLocation.ToString & """,""key"":""" & bytKey.ToString() & """,""IV"":""" & bytIV.ToString() & """}}"
            End If


            'Catch file not found error.
        Catch When Err.Number = 53 'if file not found
            edsOutput = "{""status"":""10"",""information:"":""File Not Found"",""data"":{""totalBytes"":""0"",""inputFile"":""" & SelectedFileLocation.ToString & """,""outputFile"":""" & OutputFileLocation.ToString & """,""key"":""" & bytKey.ToString() & """,""IV"":""" & bytIV.ToString() & """}}"

            'Catch all other errors. And delete partial files.
        Catch
            fsInput.Close()
            fsOutput.Close()

            If Direction = CryptoAction.ActionDecrypt Then
                Dim fileDelete As New FileInfo(OutputFileLocation)
                fileDelete.Delete()
                edsOutput = "{""status"":""11"",""information:"":""Encryption Key/Password Cannot Decrypt File"",""data"":{""totalBytes"":""0"",""inputFile"":""" & SelectedFileLocation.ToString & """,""outputFile"":""" & OutputFileLocation.ToString & """,""key"":""" & bytKey.ToString() & """,""IV"":""" & bytIV.ToString() & """}}"
            Else
                Dim fileDelete As New FileInfo(OutputFileLocation)
                fileDelete.Delete()
                edsOutput = "{""status"":""12"",""information:"":""File Cannot Be Encrypted"",""data"":{""totalBytes"":""0"",""inputFile"":""" & SelectedFileLocation.ToString & """,""outputFile"":""" & OutputFileLocation.ToString & """,""key"":""" & bytKey.ToString() & """,""IV"":""" & bytIV.ToString() & """}}"
            End If
        End Try
        Return edsOutput
    End Function
End Module
