function output_bundle = extract_cdp_data(file_in, ...
    timing_plots, fname,specific_rt_on, special_rt)
%This function contains the core code to parse out the 1553 message sets
%from CDP formatted binary files.

%% Open the input file and read the contents

fp = fopen(file_in,'r');

fseek(fp,0,'eof');
file_size=ftell(fp);
fseek(fp,0,'bof');

dump = fread(fp,file_size/4,'uint32'); %read all of the data in implicitly

fclose(fp);


%% Initialize the bit indexing and masks
%The cdp files are composed of packets 196 bytes long (49*4byte words). The
%index should go from 1, 197, etc...

%fsize is number of bytes per packet divided by the 4bytes word size
cindex = 1:196:file_size; %gets an index value for every 4B
fsize = 196/4;

%
% Numbers used for bit mask calculations (replace with someone better)
%
low6 = 63;
low5 = (2^5)-1;
high6 = 4227858432;
high5 = 4160749568;
low16 = (2^16)-1;
low16_64bit = uint64(low16);
high16 = 4294901760; %sets upper 16/32 bits high
high16_64bit = (2^64) - (2^32);
high48_64bit = (2^64) - (2^16);

%% Move through the data and pull out the data per message
% Read the file image and extract the relevant words for that packet of
% 196Bytes. Some of the words will need to have certain bits converted.
%

%preallocate the struct. Structs don't use sequential memory, but the inner
%arrays do, so this may help (may)
%From profiling, the structure resizing took 95% of the processing time.
%Oops. This should fix resizing a structure on the fly (needs a check for
%out of memory conditions though)

%
%test to see if the file size is in multiples of 196 bytes (1cdp)
%
if (mod(file_size,196) ~=0)
   %this file size is corrupt. try to salvage it by clipping off the bad
   %end
   file_size = floor(file_size/196) * 196;
   fprintf(1,'!!!! File Size for %s is corrupt or damaged. Clipping!!!!\n', ...
       fname);
end

max_size = floor(file_size/196);
cdp_data(max_size).head_pointer =0;

% Memory check TBD

fprintf(1,'*** Parsing out message data ***\n');
counter = 1;
for ii = 1:fsize:file_size/4 %we read in 4B per word
    if (mod(ii,fsize*10000) == 0)
        fprintf(1,'Now Parsing Out %d of %d\n',ii,file_size/4);
    end
    cdp_data(counter).head_pointer= dump(ii);
    cdp_data(counter).sequence_num= dump(ii+1);
    cdp_data(counter).info_word= dump(ii+2);
    cdp_data(counter).mask= dump(ii+3);
    cdp_data(counter).mask_compare= dump(ii+6);
    cdp_data(counter).control_word= dump(ii+7);
    cdp_data(counter).status_word= dump(ii+8);
    cdp_data(counter).time_tag_high= dump(ii+9);
    cdp_data(counter).time_tag_low= dump(ii+10);
    cdp_data(counter).img= dump(ii+11);
    cdp_data(counter).command_word1= dump(ii+13);
    cdp_data(counter).command_word2= dump(ii+14);
    cdp_data(counter).status_word1= dump(ii+15);
    cdp_data(counter).status_word2= dump(ii+16);
    
    % get data words
    % turn off data for quicker plots
    %!!!! These are 32bit data words (only 16bits of those should be used
    %for standard 1553 data). Through some ugly bitshifting, the lower
    %16bits are kept alive
    dword32 = uint32(dump(ii+17:ii+48));
    cdp_data(counter).data_word = ...
        double(bitand(uint64(dword32),uint64(low16_64bit)));
    
    %CDP bus taken from Status Word and is bit #7
    cdp_data(counter).bus = ...
        bitget(cdp_data(counter).status_word,7);
    
    % The CDP status word contains the Message type
    %4294967232 is the leftmost 26 bits set high, bits1-6 low)
    %63 is just the rightmost 6 bits set high
    %4227858432 is the leftmost 6 bits set high
    cdp_data(counter).number_data_words = ...
        bitand(cdp_data(counter).status_word,low6);
    
    % Type bits follow this format (taken from CDP status word bits 27-32)
    % 1=spurious message
    % 2=BC-RT
    % 4=RT-BC
    % 8=RT-RT
    % 16=Mode Code
    % 32 = Broadcast
    %
    cdp_data(counter).type_bits = ...
        bitshift(bitand(cdp_data(counter).status_word,high6),-26);
    
    switch cdp_data(counter).type_bits
        case 1
            cdp_data(counter).message_type = 'Spurious Message';
        case 2
            cdp_data(counter).message_type = 'BC-RT';
        case 4
            cdp_data(counter).message_type = 'RT-BC';
        case 8
            cdp_data(counter).message_type = 'RT-RT';
        case 16
            cdp_data(counter).message_type = 'Mode Code';
        case 32
            cdp_data(counter).message_type = 'Broadcast';
        otherwise
            fprintf(1,'!!! Warning: Mode Code Failure Msg: %d!!!\n',ii);
            cdp_data(counter).message_type = 'FAILED MODE';
    end
    
    %!! Add in the error control bits later
    
    % Command Word Parsing-brute force masking and bitshifting
    command1553 = bitand(cdp_data(counter).command_word1,low16);
    cdp_data(counter).command1553 = command1553;
    
    cdp_data(counter).rt_address = bitshift(command1553,-11);
    
    
    cdp_data(counter).rxtx = bitget(command1553,11);
    %for rxtx, 0 = receive, 1 = transmit message
    
    sub_address = bitand(bitshift(command1553,-5),low5);
    
    % bitshift(bitand(cdp_data(counter).command_word1,low16),-6);
    %sub_address = bitand(command_sa_num,low5);
    expected_words = bitand(command1553,low5);
    
    % bitshift(command_sa_num,-5);
    
    cdp_data(counter).sub_address = sub_address;
    cdp_data(counter).expected_words = expected_words;
    
    % I think expected words is the number of words the cdp packet expects,
    % which is not the same as the number of 1553 words in the message. The
    % cdp packets are composed of 32 data words, even though 1553 has 16,
    % so the word count for cdp should be 32 or 9 words.
    % if (cdp_data(counter).expected_words ~= cdp_data(counter).number_data_words)
    % fprintf(1,'!!! Error! Number of data words expected differs @count=%d\n', ...
    %        counter);
    % end
    
    
    % Time Tag Creation
    timetag = uint64(cdp_data(counter).time_tag_high);
    timetag = bitshift(timetag,32);
    timetag = bitor(timetag,cdp_data(counter).time_tag_low);
    cdp_data(counter).timetag = timetag;
    clear timetag;
    
    counter = counter +1;
end

%% Reformat for array functions
%structure format above is VERY inefficient, so using arrays to do indexing

head_pointer = zeros(1,length(cdp_data));
sequence_number = zeros(1,length(cdp_data));
timetag = zeros(1,length(cdp_data));
type_message = zeros(1,length(cdp_data));
rt_address = zeros(1,length(cdp_data));
sub_address_value = zeros(1,length(cdp_data));
rxtx = zeros(1,length(cdp_data));
message_type{length(cdp_data)}=[];
status_words{length(cdp_data)} = [];
data_words{length(cdp_data)} = []; %very important to prealloc this one
number_data_words = zeros(1,length(cdp_data));

fprintf(1,'Reformatting into arrays\n');
% This may be a lengthy process, especially if the cdp bus data is very
% large
for ii = 1:length(cdp_data)
    head_pointer(ii) = cdp_data(ii).head_pointer;
    sequence_number(ii) = cdp_data(ii).sequence_num;
    timetag(ii) = cdp_data(ii).timetag;
    type_message(ii) = cdp_data(ii).type_bits;
    rt_address(ii) = cdp_data(ii).rt_address;
    sub_address_value(ii) = cdp_data(ii).sub_address;
    rxtx(ii) = cdp_data(ii).rxtx;
    message_type{ii} = cdp_data(ii).message_type;
    status_words{ii} = cdp_data(ii).status_word;
    data_words{ii} = cdp_data(ii).data_word;
    number_data_words(ii) = cdp_data(ii).number_data_words;
end

%% Index the RT and Subaddress data locations
urt = unique(rt_address); %gets all the unique rt numbers found

out_counter = 1;

for ii = 1:length(urt)
    fprintf(1, 'Processing New RT %d\n',urt(ii));
    
    data_rt_name = genvarname(sprintf('data_RT%2d',urt(ii)));
    
    rt_index = find(rt_address == urt(ii));
    usub = unique(sub_address_value(rt_index));
    for jj = 1:length(usub)
        
        %find the index for all the values with current unique subaddress
        sa_index = find(sub_address_value(rt_index) == usub(jj));
        sa_index = rt_index(sa_index); %refactor to outer index
        
        umessage = unique(type_message(sa_index));
        
        for kk = 1:length(umessage)
            clear mindex msgindex temp_index;
            mindex = find(type_message(sa_index) == umessage(kk));
            temp_index = type_message(sa_index);
            msgindex = sa_index(mindex); %temp_index(index);
            
            for rloop = 0:1
                
                rindex = find(rxtx(msgindex) == rloop);
                
                rxtxindex = msgindex(rindex);
                if (isempty(rxtxindex)) %length(rxtxindex) >1)
                    continue;
                else
                end
                rname = unique(rxtx(rxtxindex));
                if ( (length(rname)> 1) || isempty(rname))
                    fprintf(1,'Fail in rname creation\n');
                    continue;
                end
                if (rname == 0), rstring = 'R'; else rstring='T';end
                
                fprintf(1,'\t Subaddress %d Tx = %d\n',usub(jj),rloop);
                deltat = double(timetag(rxtxindex(2:end)))- ...
                    double(timetag(rxtxindex(1:end-1)));
                
                
                %Find alternating stable times -- maybe add later
                %max
                if (timing_plots)
                    figure;
                    %stat_index=find(deltat > mean(deltat));
                    subplot(2,1,1); plot(1:length(deltat), deltat,'b.');
                end
                %the timetag is in units of 20ns, so multiply the output by
                %20ns
                mean_rate = 1/(mean(deltat)*20e-9);
                
                
                % message type display name
                mname = unique(message_type(rxtxindex));
                if ((length(mname) >1)|| (isempty(mname)))
                    fprintf(1,'Error in message type name breakout\n');
                    continue;
                end
                
                
                if (timing_plots)
                    %Upper Plot Box, Message Rate
                    ttext = sprintf('File: %s\nRT %d SubAddress %d Message Type %d:%s Rx/Tx %c\nMean Rate = %3f Hz', ...
                        fname,urt(ii),usub(jj),umessage(kk),mname{:}, ...
                        rstring,mean_rate);
                    title(ttext,'Interpreter','None');
                    grid on;
                    ylabel('Time Tag Delta (units of 20 ns)');
                    xlabel('Message Number');
                    
                    %Lower Plot Box, Histogram
                    histtext = sprintf('Frequency of Delta Times\nRT %d SubAddress %d:%s Message Type %d RxTx %c\nMean Rate = %3f Hz', ...
                        fname,urt(ii),usub(jj), ...
                        umessage(kk),mname{:},rstring,mean_rate);
                    subplot(2,1,2); hist(deltat,32);
                    title('Frequency of delta times');
                    xlabel('Time Delta Bin (units of 20 ns)');
                    ylabel('Frequency of delta');grid on;
                end
                
                % Output Statistics for generating output info
                output_stats_rt(out_counter) = urt(ii);
                output_stats_sa(out_counter) = usub(jj);
                output_stats_type(out_counter) = umessage(kk);
                output_stats_rxtx(out_counter) = rloop;
                if (rloop == 0)
                    output_stats_receive{out_counter} = 'R';
                else
                    output_stats_receive{out_counter} = 'T';
                end
                output_stats_mean_rate(out_counter) = mean_rate;
                word_count = unique(number_data_words(rxtxindex));
                if ( max(size(word_count)) > 1)
                    %found more than one word count for this message set
                    fprintf(1,'!!! Found a message set with variable wc\n');
                    output_stats_wc(out_counter) = 99;
                else
                    output_stats_wc(out_counter) = word_count;
                    
                end
                
                %store the ascii message type
                switch output_stats_type(out_counter)
                    case 1
                        message_name = 'Spurious Message';
                    case 2
                        message_name = 'BC-RT';
                    case 4
                        message_name = 'RT-BC';
                    case 8
                        message_name = 'RT-RT';
                    case 16
                        message_name = 'Mode';
                    case 32
                        message_name = 'Bcast';
                    otherwise
                        message_name = 'UNKNOWN';
                        %took care of warning earlier
                end
                output_stats_mtype{out_counter} = message_name;
                
                %
                
                
                if (specific_rt_on == 1)
                    if (urt(ii) == special_rt)
                        sa_list = 1:30;
                        
                        for sloop = 1:length(sa_list)
                            if ( ~isempty(find( (usub(jj) == sa_list(sloop)),1)))
                                %if one of the subaddresses in our list is found,
                                %then store the indices to its data items.
                                
                                eval([sprintf('bus_data.%s_SA%02d_%c', ...
                                    data_rt_name,usub(jj),rstring) ...
                                    '=  rxtxindex;']);
                            end
                        end
                    end
                else
                    sa_list = 1:30;
                    
                    for sloop = 1:length(sa_list)
                        if ( ~isempty(find( (usub(jj) == sa_list(sloop)),1)))
                            %if one of the subaddresses in our list is found,
                            %then store the indices to its data items.
                            
                            %                             eval(['bus_data.' data_rt_name sprintf('_SA%02d_%c', ...
                            %                                 usub(jj),rstring) ...
                            %                                 '=  rxtxindex;']);
                            eval([sprintf('bus_data.%s_SA%02d_%c', ...
                                data_rt_name,usub(jj),rstring) ...
                                '=  rxtxindex;']);
                            
                        end
                        
                    end
                    
                end
                
                
                out_counter = out_counter +1;
                clear deltat mname;
            end
        end
        
        clear sa_index;
    end
    clear rt_index;
end


%% Pack the output data
output_bundle.mean_rate = output_stats_mean_rate;
output_bundle.receive = output_stats_receive;
output_bundle.rt = output_stats_rt;
output_bundle.rxtx = output_stats_rxtx;
output_bundle.sa = output_stats_sa;
output_bundle.type = output_stats_type;
output_bundle.wc = output_stats_wc;
output_bundle.mtype = output_stats_mtype;
output_bundle.cdp_data = cdp_data; %very expensive, but easier to pass out
output_bundle.bus_data = bus_data;
output_bundle.data_words = data_words;



end

