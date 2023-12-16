module bitcoin_hash_par #(parameter integer NUM_OF_WORDS = 20)(
							input logic        clk, rst_n, start,
                     input logic [15:0] header_addr, hash_out_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] memory_addr,
                    output logic [31:0] memory_write_data,
                     input logic [31:0] memory_read_data);

parameter num_nonces = 16;
enum logic [2:0] {IDLE, READ, COMP1B, COMP2B, HASHFIN, WRITE} state;

logic [4:0] current_nonce;

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


// Student to add rest of the code here

//(19 words + nonce) is the message
//16 nonce values
//the first block will always be the same since its the first 16 words only the second block will change therefor the hash values from that block are always the same 
//write only h[0] for each nonce 2nd sha output

/*FSM 
state: block 1(run once):::   get hash values for first block add them to {A,B,C,D...H}
state: block 2(run for every nonce):::  get hash values and add to {A,B,C,D...H}
state: block 3(run for every nonce)::: with complete hash values from one full sha run, run it again with the 8 hash values being the message input)
state: write h[0] from each nonce to output 

challenge right now is how to send just a block at a time into the sha operator? can we pass a block into the module decleration 
sha op with just 16 words of the message sent to it. 
*/
	logic [31:0] w[16][num_nonces];
	
	logic [31:0] hash0[num_nonces], hash1[num_nonces], hash2[num_nonces], hash3[num_nonces], hash4[num_nonces], hash5[num_nonces], hash6[num_nonces], hash7[num_nonces];

	logic [31:0] A[num_nonces], B[num_nonces], C[num_nonces], D[num_nonces], E[num_nonces], F[num_nonces], G[num_nonces], H[num_nonces];
	logic [ 7:0] i, j;
	logic [15:0] next_offset; // in word address
	logic [ 7:0] num_blocks;
	logic [15:0] present_addr; //setting present addr
	logic [31:0] present_write_data;
	
	logic [ 7:0] t;
	logic [ 7:0] current_block;
	logic [63:0] size_message;
	logic [63:0] size_message_hash;


	assign mem_clk = clk;
	assign memory_addr = present_addr + next_offset;
	
	assign memory_write_data = present_write_data;
	assign num_blocks = determine_num_blocks(NUM_OF_WORDS);
	
function logic [31:0] determine_num_blocks(input logic [31:0] size);
		determine_num_blocks = (NUM_OF_WORDS+2)/16+1; //rounds up to see how many blocks we need. i.e. we cant implemant 1.8 blocks we need 2 
	endfunction
	
	function logic [31:0] word_expansion(input logic [31:0] w15, w2, w16, w7);
		logic [31:0] S1, S0;
		begin
			S0 = ror(w15, 7) ^ ror(w15, 18) ^ (w15 >> 3); //fixed equation it had 3 ror instead of a binary shift 
			S1 = ror(w2, 17) ^ ror(w2, 19) ^ (w2 >> 10);   //fixed equation it had 3 ror instead of a binary shift 
			word_expansion = w16 + S0 + w7 + S1;
		end
	endfunction


	
// SHA256 hash round
	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w, input logic [7:0] t);
		logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
		begin
			S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
			maj = (a & b) ^ (a & c) ^ (b & c);
			t2 = S0 + maj;
			S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
			ch = (e & f) ^ ((~e) & g);
			t1 = h + S1 + ch + k[t] + w;
			sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
		end
	endfunction

function logic [31:0] ror(input logic [31:0] in, input logic [7:0] s);
		begin
		   ror = (in >> s) | (in << (32-s));
		end
	endfunction

	always_ff @(posedge clk, negedge rst_n) begin
		if (!rst_n) begin
			state <= IDLE;
		end else begin 
			case (state)
			
			IDLE: begin
			if(start) begin 
						next_offset <= 0;					//by setting offset and present addr here we can start paralizing since we have to wait 2 cycles till mem address is ready 
						
						hash0[0] <= 32'h6a09e667;
						hash1[0] <= 32'hbb67ae85;
						hash2[0] <= 32'h3c6ef372;
						hash3[0] <= 32'ha54ff53a;
						hash4[0] <= 32'h510e527f;
						hash5[0] <= 32'h9b05688c;
						hash6[0] <= 32'h1f83d9ab;
						hash7[0] <= 32'h5be0cd19;
						
						present_addr <= header_addr;
						size_message <= 640;	//get the decimal value for how many bits are in the message
						size_message_hash <= 256;	//get the decimal value for how many bits are in the message

						j <= 0;
						
						state <= READ;
						mem_we <= 0; //this is 0 becasue we are reading...
						current_block <= 1;

						current_nonce<=0;

					end
			end
			
			READ: begin
				if(current_block < num_blocks) begin //checking to see if we are on the last block or not 
						if((next_offset)%16==0 && j < 15) //pre loading offset 1 now so its ready when we need  ----NOW it prealoads for each block so each block has good timing, before it would and repeat copying the message
							next_offset <= next_offset+1;
						else if(j < 16) begin //using j that way we can increment next offset freely and not worry about next block's loop, j will take care of that 
							w[j][0] <= memory_read_data;//first 16 elemnts(words) of W are coming from memory 
							next_offset <= next_offset+1;
							j<=j+1;
						end else begin
							state <= COMP1B;
							j <= 0;
							t <= 0;
							current_block<=current_block+1;
							A[0] <= hash0[0];
							B[0] <= hash1[0];
							C[0] <= hash2[0];
							D[0] <= hash3[0];
							E[0] <= hash4[0];
							F[0] <= hash5[0];
							G[0] <= hash6[0];
							H[0] <= hash7[0];
							next_offset <= next_offset-1; //ended up needing to deincrement when we leave to compute since run offset is already 1 before we run line 144 so next offset wold be 1 to big in the end
							current_nonce=0;
						end
				end else if(current_block == num_blocks) begin //checking to see if we are at last block
						if((next_offset)%16==0) //pre loading offset 1 now so its ready when we need ---NOW it prealoads for each block so each block has good timing, before it would and repeat copying the message
							next_offset <= next_offset+1;
						else if(j < (NUM_OF_WORDS%16)) begin//num words mod 16 gives us however many words will be going in the last block 
							w[j][0] <= memory_read_data;//putting in the remainder of the words left  
							next_offset <= next_offset+1;
							j<=j+1;		
						end else if(j == (NUM_OF_WORDS%16)) begin
							w[j][0] <= {1'b1, 31'b0}; //this is the first padding bit which is a 1
							next_offset <= next_offset+1;
							j<=j+1;
						end else begin	
						
						for(j=NUM_OF_WORDS%16+1;j<14;j++)begin //now we will fill from the 1 till 2 places before the end since we need the last 2 elements (64 bits) to be the size of the message
							w[j][0] <= 0;
							
							end
							
						 //first 32 bits of input message size 
							w[14][0] <= size_message[63:32];

						 //last 32 bits of input message size
							w[15][0] <= size_message[31:0];	
							
							j <= 0;
							t <= 0;
							current_block<=current_block+1;
				
					
					
							
							
						
						
						end	
			end else if(current_block>num_blocks)begin
					state<=COMP2B;
					for(current_nonce=0;current_nonce<num_nonces;current_nonce++)begin	
						for(int r=0;r<16;r++)begin
							if(r!=3)begin//if not where the nonce index 
								w[r][current_nonce]<=w[r][0];
							
							end else begin
								w[r][current_nonce]<=current_nonce;
							end
						end
					
					end
					
			
					
						end
			
			end
			
			COMP1B:begin
				
						{A[0],B[0],C[0],D[0],E[0],F[0],G[0],H[0]} <= sha256_op(A[0],B[0],C[0],D[0],E[0],F[0],G[0],H[0],w[t][0],t);
						
						if(t==15) begin
						w[15][0] <= word_expansion(w[1][0], w[14][0], w[0][0], w[9][0]);
						for(int n=0;n<15;n++)begin //shifting W array over one 
										w[n][0]<=w[n+1][0]; 
									end
						end
						t<=t+1; 
					if (t < 64&&t>15) begin 
									w[15][0] <= word_expansion(w[1][0], w[14][0], w[0][0], w[9][0]);
									{A[0],B[0],C[0],D[0],E[0],F[0],G[0],H[0]} <= sha256_op(A[0],B[0],C[0],D[0],E[0],F[0],G[0],H[0],w[15][0],t);
									
									for(int n=0;n<15;n++)begin //shifting W array over one 
										w[n][0]<=w[n+1][0]; 
									
									end
							t<=t+1; 

					end else if (t == 64) begin
						for(current_nonce=0;current_nonce<num_nonces;current_nonce++)begin	
						hash0[current_nonce] <= A[0] + hash0[0];
						hash1[current_nonce] <= B[0] + hash1[0];
						hash2[current_nonce] <= C[0] + hash2[0];
						hash3[current_nonce] <= D[0] + hash3[0];
						hash4[current_nonce] <= E[0] + hash4[0];
						hash5[current_nonce] <= F[0] + hash5[0];
						hash6[current_nonce] <= G[0] + hash6[0];
						hash7[current_nonce] <= H[0] + hash7[0];
						A[current_nonce] <= A[0] + hash0[0];
						B[current_nonce] <= B[0] + hash1[0];
						C[current_nonce] <= C[0] + hash2[0];
						D[current_nonce] <= D[0] + hash3[0];
						E[current_nonce] <= E[0] + hash4[0];
						F[current_nonce] <= F[0] + hash5[0];
						G[current_nonce] <= G[0] + hash6[0];
						H[current_nonce] <= H[0] + hash7[0];

						end
						state<=READ;
				    end  
					
					
			
			
			
			end
			
			COMP2B:begin
		
	for(current_nonce=0;current_nonce<num_nonces;current_nonce++)begin	
		
		
						{A[current_nonce],B[current_nonce],C[current_nonce],D[current_nonce],E[current_nonce],F[current_nonce],G[current_nonce],H[current_nonce]} <= sha256_op(A[current_nonce],B[current_nonce],C[current_nonce],D[current_nonce],E[current_nonce],F[current_nonce],G[current_nonce],H[current_nonce],w[t][current_nonce],t);
						if(t==15) begin//pre for word expansion 1 cycle early
							
							for(int n=0;n<15;n++)begin //shifting W array over one 
									w[n][current_nonce]<=w[n+1][current_nonce]; 
									
							end
						w[15][current_nonce] <= word_expansion(w[1][current_nonce], w[14][current_nonce], w[0][current_nonce], w[9][current_nonce]);//new W[15] value
						
						end
						t<=t+1; 
		if (t < 64&&t>15) begin 
						
						{A[current_nonce],B[current_nonce],C[current_nonce],D[current_nonce],E[current_nonce],F[current_nonce],G[current_nonce],H[current_nonce]} <= sha256_op(A[current_nonce],B[current_nonce],C[current_nonce],D[current_nonce],E[current_nonce],F[current_nonce],G[current_nonce],H[current_nonce],w[15][current_nonce],t);
							
						for(int n=0;n<15;n++)begin //shifting W array over one 
								w[n][current_nonce]<=w[n+1][current_nonce]; 
						end
						w[15][current_nonce] <= word_expansion(w[1][current_nonce], w[14][current_nonce], w[0][current_nonce], w[9][current_nonce]);
										
						t<=t+1; 
		
		end else if (t == 64) begin

							w[0][current_nonce]<=A[current_nonce] + hash0[current_nonce];
							w[1][current_nonce]<=B[current_nonce] + hash1[current_nonce];
							w[2][current_nonce]<=C[current_nonce] + hash2[current_nonce];
							w[3][current_nonce]<=D[current_nonce] + hash3[current_nonce];
							w[4][current_nonce]<=E[current_nonce] + hash4[current_nonce];
							w[5][current_nonce]<=F[current_nonce] + hash5[current_nonce];
							w[6][current_nonce]<=G[current_nonce] + hash6[current_nonce];
							w[7][current_nonce]<=H[current_nonce] + hash7[current_nonce];
							w[8][current_nonce]<={1'b1, 31'b0};
							for(int v=9;v<14;v++)begin
							w[v][current_nonce]<={32'b0};
							end
							w[14][current_nonce]<=size_message_hash[63:32];
							w[15][current_nonce]<=size_message_hash[31:0];
							state<=HASHFIN;
							hash0[current_nonce] <= 32'h6a09e667;
							hash1[current_nonce] <= 32'hbb67ae85;
							hash2[current_nonce] <= 32'h3c6ef372;
							hash3[current_nonce] <= 32'ha54ff53a;
							hash4[current_nonce] <= 32'h510e527f;
							hash5[current_nonce] <= 32'h9b05688c;
							hash6[current_nonce] <= 32'h1f83d9ab;
							hash7[current_nonce] <= 32'h5be0cd19;
							A[current_nonce] <= 32'h6a09e667;
							B[current_nonce] <= 32'hbb67ae85;
							C[current_nonce] <= 32'h3c6ef372;
							D[current_nonce] <= 32'ha54ff53a;
							E[current_nonce] <= 32'h510e527f;
							F[current_nonce] <= 32'h9b05688c;
							G[current_nonce] <= 32'h1f83d9ab;
							H[current_nonce] <= 32'h5be0cd19;
							t <= 0;
						end 
									
				
			
			
	
	end
		
			end
			
HASHFIN:begin
					
					
	for(current_nonce=0;current_nonce<num_nonces;current_nonce++)begin	
		
					
						{A[current_nonce],B[current_nonce],C[current_nonce],D[current_nonce],E[current_nonce],F[current_nonce],G[current_nonce],H[current_nonce]} <= sha256_op(A[current_nonce],B[current_nonce],C[current_nonce],D[current_nonce],E[current_nonce],F[current_nonce],G[current_nonce],H[current_nonce],w[t][current_nonce],t);

						if(t==15)begin
						w[15][current_nonce]<=word_expansion(w[1][current_nonce], w[14][current_nonce], w[0][current_nonce], w[9][current_nonce]);
						for(int n=0;n<15;n++)begin //shifting W array over one 
										w[n][current_nonce]<=w[n+1][current_nonce]; 
									end
						end
						
							t<=t+1; 
					if (t < 64&&t>15) begin 
						w[15][current_nonce] <= word_expansion(w[1][current_nonce], w[14][current_nonce], w[0][current_nonce], w[9][current_nonce]);
						{A[current_nonce],B[current_nonce],C[current_nonce],D[current_nonce],E[current_nonce],F[current_nonce],G[current_nonce],H[current_nonce]} <= sha256_op(A[current_nonce],B[current_nonce],C[current_nonce],D[current_nonce],E[current_nonce],F[current_nonce],G[current_nonce],H[current_nonce],w[15][current_nonce],t);
						for(int n=0;n<15;n++)begin //shifting W array over one 
								w[n][current_nonce]<=w[n+1][current_nonce]; 
							end

								t<=t+1; 
					
					end else if (t == 64) begin
						hash0[current_nonce] <= A[current_nonce] + hash0[current_nonce];
						/*hash1[current_nonce] <= B[current_nonce] + hash1[current_nonce];
						hash2[current_nonce] <= C[current_nonce] + hash2[current_nonce];
						hash3[current_nonce] <= D[current_nonce] + hash3[current_nonce];
						hash4[current_nonce] <= E[current_nonce] + hash4[current_nonce];
						hash5[current_nonce] <= F[current_nonce] + hash5[current_nonce];
						hash6[current_nonce] <= G[current_nonce] + hash6[current_nonce];
						hash7[current_nonce] <= H[current_nonce] + hash7[current_nonce];*/
						state <= WRITE;
						i <= 0;
						next_offset<=0;
						mem_we <= 1;
						present_addr <= hash_out_addr;
						
					
					
					end 
					
				end
			
			
						
			
						
			
			end
			
			WRITE: begin

			case(i)
						0: begin
							present_write_data <= hash0[i];
										
						end
						1: begin
							present_write_data <= hash0[i];
							
						
						end
						2: begin
							present_write_data <= hash0[i];
						end
						3: begin
							present_write_data <= hash0[i];
								
						end
						4: begin
							present_write_data <= hash0[i];							
						end
						5: begin
							present_write_data <= hash0[i];						
						end
						6: begin
							present_write_data <= hash0[i];							
						end
						7:begin
							present_write_data <= hash0[i];							
						end 
						8:begin
							present_write_data <= hash0[i];
						end
						9:begin
							present_write_data <= hash0[i];							
						end
						10:begin
							present_write_data <= hash0[i];							
						end
						11:begin
							present_write_data <= hash0[i];							
						end
						12:begin
							present_write_data <= hash0[i];							
						end
						13:begin
							present_write_data <= hash0[i];							
						end
						14:begin
							present_write_data <= hash0[i];							
						end
						15:begin
							present_write_data <= hash0[i];							
						end
						16:begin
							state <= IDLE;							
						end			
				endcase
				i<=i+1;
					if(i!=0)begin
					next_offset<=next_offset+1;
			end
		end
			
		endcase

end

end
assign done=(state==IDLE);

endmodule: bitcoin_hash_par
