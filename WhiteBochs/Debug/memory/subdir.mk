################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../memory/memory.o 

CC_SRCS += \
../memory/memory.cc 

OBJS += \
./memory/memory.o 

CC_DEPS += \
./memory/memory.d 


# Each subdirectory must supply rules for building sources it contributes
memory/%.o: ../memory/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


