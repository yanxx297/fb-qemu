################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../disasm/dis_decode.o \
../disasm/dis_groups.o \
../disasm/resolve.o \
../disasm/syntax.o 

CC_SRCS += \
../disasm/dis_decode.cc \
../disasm/dis_groups.cc \
../disasm/resolve.cc \
../disasm/syntax.cc 

OBJS += \
./disasm/dis_decode.o \
./disasm/dis_groups.o \
./disasm/resolve.o \
./disasm/syntax.o 

CC_DEPS += \
./disasm/dis_decode.d \
./disasm/dis_groups.d \
./disasm/resolve.d \
./disasm/syntax.d 


# Each subdirectory must supply rules for building sources it contributes
disasm/%.o: ../disasm/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


