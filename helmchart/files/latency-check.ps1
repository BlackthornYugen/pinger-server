#!/usr/bin/env pwsh

Param (
    # Port number to listen on
    [int] $ListenPort = 11000,
    # Port number to send data to
    [int] $SendPort = 11000,
    # Timeout in milliseconds for sending data
    [int] $SendTimeout = 1000,
    # Timeout in milliseconds for receiving data
    [int] $ReceiveTimeout = 1000,
    # Address to send data to
    [string] $SendAddress = "127.0.0.1",
    # Message to send
    [string] $Message = "Hello",
    # key used for integrity / authentication
    [string] $HmacKey = "changeit",
    # key used to hide content
    [byte[]] $AesKey,
    # switch to run a server
    [Alias("Server")]
    [switch] $RunServer
)

class Message {
    [byte[]] $IV
    [byte[]] $HMAC
    [byte[]] $Message

    Message([byte[]]$Message) {
        $this.IV = New-Object byte[] 16
        $this.Message = $Message
    }

    Message([byte[]]$Message, [System.Security.Cryptography.Aes]$Key) {
        $this.IV = New-Object byte[] 16
        $this.Plaintext = New-Object byte[] ($Message.Length - 16)
        $ciphertext = New-Object byte[] ($Message.Length - 16)
        [Array]::Copy($this.Message, $Key.IV, 16)
        [Array]::Copy($this.Message, 16, $ciphertext, 0, ($Message.Length - 16))
        # return $AES.DecryptCBC($ciphertext, $iv)
    }

    [byte[]]GetEncoded() {
        return $this.IV + $this.Message
    }
    
    [byte[]]GetEncoded([System.Security.Cryptography.Aes]$Key) {
        $this.IV = $Key.IV
        # return $this.IV + $this.Message
        return $this.IV + $Key.EncryptCbc($this.Message, $this.iv)
    }
}

$AES = [System.Security.Cryptography.Aes]::Create()
if ( $null -ne $AesKey )
{
    $AES.GenerateIV()
    $AES.Key = $aesKey
}

$encoder = [system.Text.Encoding]::UTF8

function Invoke-Ping {
    param (
        [System.Net.Sockets.UdpClient] $client
    )

    $sendBytes = $encoder.GetBytes($Message)
    
    if ($null -ne $aesKey) 
    {
        $sendBytes = [Message]::New($sendBytes).GetEncoded($AES)
    }
    
    # Measure the time it takes to send and receive data
    # Send the message
    $transmittedBytes = $client.Send($sendBytes, $sendBytes.Length, $SendAddress, $SendPort)
    $sendBytes | Format-Hex | Out-String | Write-Debug
    Write-Debug "$sendAddress $sendPort"
    # Check if the message was sent successfully
    if ($transmittedBytes -gt 0)
    {
        $RemoteIpEndPoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    
        try
        {
            # Receive the response message
            $receiveBytes = $client.Receive([ref]$RemoteIpEndPoint);

            # Convert the response message to a string
            $returnData = $encoder.GetString($receiveBytes);
            
            # Check if the response message contains any non-printable characters
            if ( $returnData -cmatch '[^\x20-\x7F]' ) 
            {
                # Found non-printable chars, use base64 to encode.
                $returnData = [Convert]::ToBase64String($receiveBytes)
            }
        }
        catch [System.Exception]
        {
            Write-Debug "Caught exception -> $_"
        }
    }
}

function Start-PingServer {
    param (
        [System.Net.Sockets.UdpClient] $client
    )

    $RemoteIpEndPoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    while ($true) {
        $receiveBytes = $null
        try 
        {
            $receiveBytes = $client.Receive([ref]$RemoteIpEndPoint)
            
    
            if ($null -ne $aesKey) 
            {
                $iv = New-Object byte[] 16
                $ciphertext = New-Object byte[] ($receiveBytes.Length - 16)
                [Array]::Copy($receiveBytes, $iv, 16)
                [Array]::Copy($receiveBytes, 16, $ciphertext, 0, ($receiveBytes.Length - 16))
                $receiveBytes = $AES.DecryptCBC($ciphertext, $iv)
            }
        }
        catch [System.Exception]
        {
            Write-Debug "Caught Receive Exception -> $_"
        }
    
        if ($receiveBytes -gt 0)
        {
            $client.Send($receiveBytes, $receiveBytes.Length, $RemoteIpEndPoint.Address, $RemoteIpEndPoint.Port) | Write-Debug
    
            $returnData = $encoder.GetString($receiveBytes)
            if ( $returnData -cmatch '[^\x20-\x7F]' ) {
                # Found non-printable chars, use base64 to encode.
                $returnData = [Convert]::ToBase64String($receiveBytes)
            }
            
            Write-Output "{`"message`":`"$returnData`",`"address`":`"$($RemoteIpEndPoint.Address):$($RemoteIpEndPoint.Port)`"}"

        }
    }
}

try {
    $client = [System.Net.Sockets.UdpClient]::new($ListenPort)
    $client.Client.SendTimeout = $SendTimeout;
    $client.Client.ReceiveTimeout = $ReceiveTimeout;

    if ( $RunServer ) 
    {
        Start-PingServer $client
    }
    else
    {
        Measure-Command { 
            Invoke-Ping $client 
        } | ForEach-Object {
            Write-Output "$(Get-Date): $($_.TotalMilliseconds)ms"
        }
    }
}
finally {
    $client.Close()
}