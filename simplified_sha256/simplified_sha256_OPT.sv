/// Figure out how we are dealing with the functions and the wt variable


module simplified_sha256_OPT #(parameter integer NUM_OF_WORDS = 40)(
 input logic  clk, rst_n, start,
 input logic  [15:0] input_addr, hash_addr,
 output logic done, memory_clk, enable_write,
 output logic [15:0] memory_addr,
 output logic [31:0] memory_write_data,
 input logic [31:0] memory_read_data);

// (clk, reset_n, start, message_addr, output_addr, done, mem_clk,
// mem_we, mem_addr, mem_write_data, mem_read_data);
// FSM state variables 
	enum logic [2:0] {IDLE, READ, COMPUTE, WRITE} state;

	// parameter integer SIZE = 0; 

	// NOTE : Below mentioned frame work is for reference purpose.
	// Local variables might not be complete and you might have to add more variables
	// or modify these variables. Code below is more as a reference.

	// Local variables
	logic [31:0] w[16];
	
	logic [31:0] S0,S1;
	logic [31:0] hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7;
	logic [31:0] A, B, C, D, E, F, G, H;
	logic [ 7:0] i, j;
	logic [15:0] next_offset; // in word address
	logic [ 7:0] num_blocks;
	logic [15:0] present_addr; //setting present addr
	logic [31:0] present_write_data;
	
	logic [ 7:0] t;
	logic [ 7:0] current_block;
	logic [63:0] size_message; //need size of message for last block

	// SHA256 K constants
	parameter int k[0:63] = '{
	   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
	   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
	   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
	   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
	   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
	   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
	   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
	   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
	};


	// Generate request to memory
	// for reading from memory to get original message
	// for writing final computed has value
	assign memory_clk = clk;
	assign memory_addr = present_addr + next_offset;
	assign memory_we = enable_write;
	assign memory_write_data = present_write_data;


	assign num_blocks = determine_num_blocks(NUM_OF_WORDS);

	// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
	// Function to determine number of blocks in memory to fetch
	function logic [15:0] determine_num_blocks(input logic [31:0] size);
		determine_num_blocks = (32*NUM_OF_WORDS+64+1+512-1)/512; //rounds up to see how many blocks we need. i.e. we cant implemant 1.8 blocks we need 2 
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



	// Right Rotation Example : right rotate input x by r
	// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
	// lets say r = 4
	// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
	// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
	// final right rotate expression is = (x >> r) | (x << (32-r));
	// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
	// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
	// Right rotation function

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
				// Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
				IDLE: begin 
					if(start) begin 
						next_offset <= 0;					//by setting offset and present addr here we can start paralizing since we have to wait 2 cycles till mem address is ready 
						hash0 <= 32'h6a09e667;
						hash1 <= 32'hbb67ae85;
						hash2 <= 32'h3c6ef372;
						hash3 <= 32'ha54ff53a;
						hash4 <= 32'h510e527f;
						hash5 <= 32'h9b05688c;
						hash6 <= 32'h1f83d9ab;
						hash7 <= 32'h5be0cd19;
						present_addr <= input_addr;
						size_message <= 32*NUM_OF_WORDS; //get the decimal value for how many bits are in the message
						j <= 0;
						t <= 1;
						state <= READ;
						current_block <= 1;
						S0 <= 0;
						S1 <= 0;
					end
					
				end

				READ: begin
					enable_write <= 0; //this is 0 becasue we are reading...
					if(current_block != num_blocks) begin //checking to see if we are on the last block or not 
						if((next_offset)%16==0 && j < 15) //pre loading offset 1 now so its ready when we need  ----NOW it prealoads for each block so each block has good timing, before it would and repeat copying the message
							next_offset <= next_offset+1;
						else if(j < 16) begin //using j that way we can increment next offset freely and not worry about next block's loop, j will take care of that 
							w[j] <= memory_read_data;//first 16 elemnts(words) of W are coming from memory 
							next_offset<=next_offset+1;
							j<=j+1;
						end else begin
							state <= COMPUTE;
							j <= 0;
							t <= 0;
							current_block<=current_block+1;
							A <= hash0;
							B <= hash1;
							C <= hash2;
							D <= hash3;
							E <= hash4;
							F <= hash5;
							G <= hash6;
							H <= hash7;
							
							next_offset<=next_offset-1;; //ended up needing to deincrement when we leave to compute since run offset is already 1 before we run line 144 so next offset wold be 1 to big in the end
							
						end
					end else if(current_block == num_blocks) begin //checking to see if we are at last block
						if((next_offset)%16==0) //pre loading offset 1 now so its ready when we need ---NOW it prealoads for each block so each block has good timing, before it would and repeat copying the message
							next_offset <= next_offset+1;
						else if(j < (NUM_OF_WORDS%16)) begin//num words mod 16 gives us however many words will be going in the last block 
							w[j] <= memory_read_data;//putting in the remainder of the words left  
							next_offset<=next_offset+1;
							j<=j+1;		
						end else if(j == (NUM_OF_WORDS%16)) begin
							w[j] <= {1'b1, 31'b0}; //this is the first padding bit which is a 1
							next_offset<=next_offset+1;
							j<=j+1;
						end else begin
						
						
						for(j=NUM_OF_WORDS%16+1;j<14;j++)begin //now we will fill from the 1 till 2 places before the end since we need the last 2 elements (64 bits) to be the size of the message
							w[j] <= 0;
							
							end
							
						 //first 32 bits of input message size 
							w[14] <= size_message[63:32];
							
							
						 //last 32 bits of input message size
							w[15] <= size_message[31:0];
							
							
							
							
							state <= COMPUTE;
							j <= 0;
							t <= 0;
							current_block<=current_block+1;
							A <= hash0;
							B <= hash1;
							C <= hash2;
							D <= hash3;
							E <= hash4;
							F <= hash5;
							G <= hash6;
							H <= hash7;
							
						end
					end
				end
				
				// Fetch message in 512-bit block size
				// For each of 512-bit block initiate hash value computation

				// For each block compute hash function
				// Go back to BLOCK stage after each block hash computation is completed and if
				// there are still number of message blocks available in memory otherwise
				// move to WRITE stage
				COMPUTE: begin 

					if (t < 16) begin
						if(t==15) begin
						w[15] <= word_expansion(w[1], w[14], w[0], w[9]);
						for(int n=0;n<15;n++)begin //shifting W array over one 
										w[n]<=w[n+1]; 
									end
						end
			
					end else if (t < 64) begin 
									w[15] <= word_expansion(w[1], w[14], w[0], w[9]);
									{A,B,C,D,E,F,G,H} <= sha256_op(A,B,C,D,E,F,G,H,w[15],t);
									
									for(int n=0;n<15;n++)begin //shifting W array over one 
										w[n]<=w[n+1]; 
									end
									
				
					end else if (t == 64) begin
						hash0 <= A + hash0;
						hash1 <= B + hash1;
						hash2 <= C + hash2;
						hash3 <= D + hash3;
						hash4 <= E + hash4;
						hash5 <= F + hash5;
						hash6 <= G + hash6;
						hash7 <= H + hash7;
						
						if (current_block > num_blocks)begin
							state <= WRITE;
							i <= 0;
							next_offset<=0;
							enable_write <= 1;
							present_addr <= hash_addr;
						end else
							state <= READ;
					
					end
					if(t<16) begin //created to condition that both go into sha operation for each t<x case 
					{A,B,C,D,E,F,G,H} <= sha256_op(A,B,C,D,E,F,G,H,w[t],t);
					
					end
				
					t<=t+1;				
					
				end				
				WRITE: begin
						
						
						
					case(i)
						0: begin
							present_write_data <= hash0;
							
							
					
						end
						1: begin
							present_write_data <= hash1;
							
						
						end
						2: begin
							present_write_data <= hash2;
							
						end
						3: begin
							present_write_data <= hash3;
							
							
						end
						4: begin
							present_write_data <= hash4;
							
						end
						5: begin
							present_write_data <= hash5;
						
						end
						6: begin
							present_write_data <= hash6;
							
						end
						7:begin
							present_write_data <= hash7;
							
							
						end 
						8:begin
							state <= IDLE;
						end
					
				endcase
				i<=i+1;
					if(i!=0)begin
					next_offset++;
			end
		end
				
			endcase
			
			
		end
	
	end
assign done=(state==IDLE);


	// SHA-256 FSM 
	// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
	// and write back hash value back to memory


	// Generate done when SHA256 hash computation has finished and moved to IDLE state
endmodule: simplified_sha256_OPT