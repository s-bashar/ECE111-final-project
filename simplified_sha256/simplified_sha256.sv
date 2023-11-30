module simplified_sha256 #(parameter integer NUM_OF_WORDS = 40)(
 input logic  clk, rst_n, start,
 input logic  [15:0] input_addr, hash_addr,
 output logic done, memory_clk, enable_write,
 output logic [15:0] memory_addr,
 output logic [31:0] memory_write_data,
 input logic [31:0] memory_read_data);

// (clk, reset_n, start, message_addr, output_addr, done, mem_clk,
// mem_we, mem_addr, mem_write_data, mem_read_data);
// FSM state variables 
	enum logic [2:0] {IDLE, READ, COMPUTE, WRITE} state,next_state;

	// parameter integer SIZE = 0; 

	// NOTE : Below mentioned frame work is for reference purpose.
	// Local variables might not be complete and you might have to add more variables
	// or modify these variables. Code below is more as a reference.

	// Local variables
	logic [31:0] w[64];
	logic [31:0] message[16];
	logic [31:0] wt;
	logic [31:0] S0,S1;
	logic [31:0] hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7;
	logic [31:0] A, B, C, D, E, F, G, H;
	logic [ 7:0] i, j;
	logic [15:0] next_offset; // in word address
	logic [ 7:0] num_blocks;
	logic [15:0] present_addr; //setting present addr
	logic [31:0] present_write_data;
	logic [512:0] data_read;
	logic [ 7:0] tstep;
	logic current_block;
	logic [63:0]size_message; //need size of message for last block

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
	assign tstep = (i - 1);

	// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
	// Function to determine number of blocks in memory to fetch
	function logic [15:0] determine_num_blocks(input logic [31:0] size);
		determine_num_blocks = (32*NUM_OF_WORDS+64+1+512-1)/512; //rounds up to see how many blocks we need. i.e. we cant implemant 1.8 blocks we need 2 
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
						size_message <= size_message; //binary representation of this decimal value 
						j <= 0;
					end
					state <= READ;
				end

				READ: begin
					enable_write <= 0; //this is 0 becasue we are reading...
					if(current_block != num_blocks) begin //checking to see if we are on the last block or not 
						if(next_offset == 0) //pre loading offset 1 now so its ready when we need
							next_offset <= 1;
						else if(j < 16) begin //using j that way we can increment next offset freely and not worry about next block's loop, j will take care of that 
							w[next_offset] <= memory_read_data;//first 16 elemnts(words) of W are coming from memory 
							next_offset++;
							j++;
						end else begin
							state <= COMPUTE; //we are ready to move to compute state for this block since it is ready 
							j <= 0;
							current_block++;
						end
					end else if(current_block == num_blocks) begin //checking to see if we are at last block
						if(next_offset == 0) //pre loading offset 1 now so its ready when we need
							next_offset <= 1;
						else if(j < (NUM_OF_WORDS%16)) begin//num words mod 16 gives us however many words will be going in the last block 
							w[next_offset] <= memory_read_data;//putting in the remainder of the words left  
							next_offset++;
							j++;		
						end else if(j == (NUM_OF_WORDS%16)) begin
							w[next_offset] <= {1'b1, 31'b0}; //this is the first padding bit which is a 1
							next_offset++;
							j++;
						end else if(j < 14) begin //now we will fill from the 1 till 2 places before the end since we need the last 2 elements (64 bits) to be the size of the message
							w[next_offset] <= 0;
							next_offset++;
							j++;
						end else if(j == 14) begin //first 32 bits of input message size 
							w[next_offset] <= size_message[63:32];
							next_offset++;
							j++;
						end else if(j == 15) begin //last 32 bits of input message size
							w[next_offset] <= size_message[31:0];
							next_offset++;
							j++;
						end else begin
							state <= COMPUTE;
							j <= 0;
							current_block++;
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
					state <= READ;
				end

				// h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
				// h0 to h7 after compute stage has final computed hash value
				// write back these h0 to h7 to memory starting from output_addr
				WRITE: begin
					
				end
				
			endcase
			done <= (state == IDLE);
		end
	end



	// SHA-256 FSM 
	// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
	// and write back hash value back to memory


	// Generate done when SHA256 hash computation has finished and moved to IDLE state
endmodule: simplified_sha256
