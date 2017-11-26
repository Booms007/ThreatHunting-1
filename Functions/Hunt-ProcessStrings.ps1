function Hunt-ProcessStrings {
    <#
    .Synopsis 
        Gets a list of strings from the process image on disk on a given system.

    .Description 
        Gets a list of strings from the process image on disk on a given system.

    .Parameter Computer  
        Computer can be a single hostname, FQDN, or IP address.

    .Parameter ToolLocation
        The location of Sysinternals Strings.exe/Strings64.exe. This parameter is manadatory
        and is how the function gets the list of strings.

    .Parameter Fails  
        Provide a path to save failed systems to.

    .Example 
        Hunt-ProcessStrings -Toollocation c:\tools\sysinternals
        Hunt-ProcessStrings SomeHostName.domain.com -Toollocation c:\tools\sysinternals
        Get-Content C:\hosts.csv | Hunt-ProcessStrings -Toollocation c:\tools\sysinternals
        Hunt-ProcessStrings $env:computername -Toollocation c:\tools\sysinternals
        Get-ADComputer -filter * | Select -ExpandProperty Name | Hunt-ProcessStrings -Toollocation c:\tools\sysinternals

    .Notes 
        Updated: 2017-11-26

        Contributing Authors:
            Jeremy Arnold
            
        LEGAL: Copyright (C) 2017
        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.
    
        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
        
    .LINK
        https://github.com/DLACERT/ThreatHunting
    #>

    param(
    	[Parameter(ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        $Computer = $env:COMPUTERNAME,
        [Parameter(mandatory=$true, HelpMessage="Specify the location of Sysinternal tool 'strings.exe' or 'strings64.exe'")]
        [string]$ToolLocation,
        [Parameter()]
        $Fails
    );

	begin{

        $datetime = Get-Date -Format "yyyy-MM-dd_hh.mm.ss.ff";
        Write-Information -MessageData "Started at $datetime" -InformationAction Continue;

        $stopwatch = New-Object System.Diagnostics.Stopwatch;
        $stopwatch.Start();

        $total = 0;

        class ProcessStrings
        {
            [String] $Computer
            [dateTime] $DateScanned
            [string] $ProcessLocation
            [string] $String
        };
	};

    process{

        $Computer = $Computer.Replace('"', '');  # get rid of quotes, if present
        $remoteOS64 = Invoke-Command -ComputerName $Computer -ErrorAction SilentlyContinue -ScriptBlock {

            $remoteOS64 = [environment]::Is64BitOperatingSystem;
        
            return $remoteOS64;
        };
      
        if ($remoteOS64){$tool = 'strings64.exe'} else {$tool = 'strings.exe'};
        
        Write-Verbose ("{0}: Copying {1} to {0}." -f $Computer, $tool);
        
        try
        {
            Copy-Item -Path $($ToolLocation+'\'+$tool) -Destination $('\\'+$Computer+'\c$\temp\'+$tool); 
        }
        catch
        {
            $Error.exception;
        }

        $processStrings = $null;
        $processStrings = Invoke-Command -ComputerName $Computer -ErrorAction SilentlyContinue -ScriptBlock { 
            $processStrings = @()
            $processes = Get-Process | Where-Object {$_.Path -ne $null} | Select-Object -Unique path
            foreach ($process in $processes.path){

                $processStrings += [pscustomobject] @{Process = $process; String = Invoke-Expression "C:\temp\$tool -n 7 -nobanner -accepteula '$process'"}
            
            }
            return $processStrings;
        
        };
            
        if ($processStrings) {
            [regex]$regexString = '(?:(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?)'; #credit to article - 8 Regular expressions you should know, Vasili
            [regex]$regexIP = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])';#credit to article - 8 Regular expressions you should know, Vasili
            $outputArray = @();
            foreach ($process in $processStrings) {
                foreach ($string in $process.string){

                    if (($string -match $regexString) -or ($string -match $regexIP)){
                                        
                        $output = $null;
                        $output = [ProcessStrings]::new();
    
                        $output.Computer = $Computer;
                        $output.DateScanned = Get-Date -Format u;
    
                        $output.ProcessLocation = $process.process;
                        $output.String = $string;
                                        
                        $outputArray += $output;

                    };

                };

            };
            Remove-Item -Path $('\\'+$Computer+'\c$\temp\'+$tool);
            return $outputArray;

        }
        else {
            
            Write-Verbose ("{0}: System failed." -f $Computer);
            if ($Fails) {
                
                $total++;
                Add-Content -Path $Fails -Value ("$Computer");
            }
            else {
                
                $output = $null;
                $output = [Handles]::new();

                $output.Computer = $Computer;
                $output.DateScanned = Get-Date -Format u;
                
                $total++;
                return $output;
            };
        };
    };

    end {

        $elapsed = $stopwatch.Elapsed;

        Write-Verbose ("Total Systems: {0} `t Total time elapsed: {1}" -f $total, $elapsed);
    };
};